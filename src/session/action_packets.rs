//! Action packet handling for Session.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::aes128_ecb_decrypt;
use crate::error::Result;
use crate::fs::Node;
use crate::session::Session;
use crate::session::core::Contact;
use crate::session::key_sync::{ActionPacketContactUpdate, ActionPacketKeyWork};

#[derive(Debug, Clone)]
pub(crate) struct ActionPacketDispatchResult {
    pub(crate) durable_tree_changed: bool,
    pub(crate) ap_pk_seen: bool,
    pub(crate) pending_keys_fetch: bool,
    pub(crate) deferred_key_work: Option<ActionPacketKeyWork>,
}

impl Session {
    fn extract_seqtag_from_response(response: &Value) -> Option<String> {
        if let Some(st) = response.get("st").and_then(|v| v.as_str()) {
            return Some(st.to_string());
        }
        if let Some(arr) = response.as_array()
            && let Some(st) = arr.first().and_then(|v| v.as_str())
        {
            return Some(st.to_string());
        }
        None
    }

    pub(crate) fn track_seqtag_from_response(&mut self, response: &Value) -> Option<String> {
        self.apply_request_seqtag(Self::extract_seqtag_from_response(response))
    }

    pub(crate) async fn dispatch_action_packets(
        &mut self,
        packets: &[Value],
    ) -> Result<ActionPacketDispatchResult> {
        let mut changed_handles = Vec::new();
        let mut contact_updates: Vec<ActionPacketContactUpdate> = Vec::new();
        let mut share_changed = false;
        let mut durable_tree_changed = false;
        let mut key_event = false;
        let mut saw_pk = false;
        let mut share_packets = Vec::new();
        let mut stale_user_attrs = HashSet::new();

        for pkt in packets {
            if let Some(obj) = pkt.as_object() {
                if let Some(st) = obj.get("st").and_then(|v| v.as_str())
                    && self.current_seqtag.as_deref() == Some(st)
                {
                    self.current_seqtag_seen = true;
                }

                if let Some(origin) = obj.get("i").and_then(|v| v.as_str())
                    && origin == self.session_id()
                {
                    let action = obj.get("a").and_then(|v| v.as_str());
                    if !matches!(action, Some("d") | Some("t")) {
                        continue;
                    }
                }

                Self::extract_handles_from_action(obj, &mut changed_handles);
                if obj.get("a").and_then(|v| v.as_str()) == Some("pk") {
                    saw_pk = true;
                }
                if Self::is_key_attr_update(obj) {
                    key_event = true;
                }
                if obj.get("a").and_then(|v| v.as_str()) == Some("ua") {
                    let skip_refetch =
                        obj.get("st").and_then(|v| v.as_str()) == self.current_seqtag.as_deref();
                    if !skip_refetch {
                        self.collect_user_attr_versions(obj, &mut stale_user_attrs);
                    }
                }
                if let Some(update) = Self::extract_contact_update(obj)? {
                    contact_updates.push(update);
                }
                let is_share_action = matches!(
                    obj.get("a").and_then(|v| v.as_str()),
                    Some("s") | Some("s2")
                );
                if is_share_action {
                    share_changed = true;
                    share_packets.push(Value::Object(obj.clone()));
                } else if self.handle_actionpacket_nodes(obj)? {
                    durable_tree_changed = true;
                }
            }
        }

        if !contact_updates.is_empty() {
            for (_h, _ed, _cu, _verified, contact) in &contact_updates {
                if let Some(c) = contact {
                    let needs_update = self
                        .contacts
                        .get(&c.handle)
                        .map(|existing| {
                            existing.last_updated != c.last_updated
                                || existing.status != c.status
                                || existing.email != c.email
                        })
                        .unwrap_or(true);
                    if needs_update {
                        self.contacts.insert(c.handle.clone(), c.clone());
                    }
                }
            }
        }

        let stale_key_attrs: Vec<String> = stale_user_attrs
            .into_iter()
            .filter(|attr| Self::is_key_attr(attr))
            .collect();
        if !stale_key_attrs.is_empty() {
            key_event = true;
        }

        if share_changed {
            key_event = true;
        }

        let needs_key_work = key_event
            || !changed_handles.is_empty()
            || share_changed
            || !share_packets.is_empty()
            || !stale_key_attrs.is_empty()
            || !contact_updates.is_empty();

        let pending_keys_fetch = saw_pk && self.key_manager.generation > 0 && self.state_current;

        let deferred_key_work = needs_key_work.then_some(ActionPacketKeyWork {
            share_changed,
            share_packets,
            changed_handles,
            stale_key_attrs,
            contact_updates,
        });

        Ok(ActionPacketDispatchResult {
            durable_tree_changed,
            ap_pk_seen: saw_pk,
            pending_keys_fetch,
            deferred_key_work,
        })
    }

    fn extract_handles_from_action(obj: &serde_json::Map<String, Value>, out: &mut Vec<String>) {
        for key in ["n", "p", "h", "t", "k"] {
            if let Some(v) = obj.get(key).and_then(|v| v.as_str()) {
                out.push(v.to_string());
            }
        }
        if let Some(arr) = obj.get("c").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(h) = item.get("h").and_then(|v| v.as_str()) {
                    out.push(h.to_string());
                }
            }
        }
    }

    fn is_key_attr_update(obj: &serde_json::Map<String, Value>) -> bool {
        let Some(action) = obj.get("a").and_then(|v| v.as_str()) else {
            return false;
        };
        if action != "ua" {
            return false;
        }
        let Some(attrs) = obj.get("ua").and_then(|v| v.as_array()) else {
            return false;
        };
        attrs
            .iter()
            .filter_map(|v| v.as_str())
            .any(Self::is_key_attr)
    }

    fn is_key_attr(attr: &str) -> bool {
        matches!(
            attr,
            "^!keys"
                | "*keyring"
                | "*~usk"
                | "*~jscd"
                | "+puCu255"
                | "+puEd255"
                | "+sigCu255"
                | "+sigPubk"
        )
    }

    fn collect_user_attr_versions(
        &self,
        obj: &serde_json::Map<String, Value>,
        stale: &mut HashSet<String>,
    ) {
        let Some(attrs) = obj.get("ua").and_then(|v| v.as_array()) else {
            return;
        };
        let Some(versions) = obj.get("v").and_then(|v| v.as_array()) else {
            return;
        };
        if attrs.len() != versions.len() {
            return;
        }

        for (attr_val, ver_val) in attrs.iter().zip(versions.iter()) {
            let Some(attr) = attr_val.as_str() else {
                continue;
            };
            let Some(version) = ver_val.as_str() else {
                continue;
            };
            if self.user_attr_versions.get(attr).map(|v| v.as_str()) != Some(version) {
                stale.insert(attr.to_string());
            }
        }
    }

    fn handle_actionpacket_nodes(&mut self, obj: &serde_json::Map<String, Value>) -> Result<bool> {
        let Some(action) = obj.get("a").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        match action {
            "t" => self.handle_actionpacket_newnodes(obj),
            "u" => self.handle_actionpacket_update_node(obj),
            "d" => self.handle_actionpacket_delete_node(obj),
            "ph" => self.handle_actionpacket_public_link(obj),
            "s" | "s2" => self.handle_actionpacket_share(obj),
            "fa" => self.handle_actionpacket_file_attr(obj),
            "psts" | "psts_v2" | "ftr" => self.handle_actionpacket_upgrade(obj),
            _ => Ok(false),
        }
    }

    fn handle_actionpacket_upgrade(
        &mut self,
        _obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        // SDK triggers account_updated and user alerts; we currently no-op.
        Ok(false)
    }

    fn handle_actionpacket_file_attr(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("h").and_then(|v| v.as_str()) else {
            return Ok(false);
        };
        let Some(fa) = obj.get("fa").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        for node in &mut self.nodes {
            if node.handle == handle {
                if node.file_attr.as_deref() != Some(fa) {
                    node.file_attr = Some(fa.to_string());
                    return Ok(true);
                }
                return Ok(false);
            }
        }

        Ok(false)
    }

    fn handle_actionpacket_share(&mut self, obj: &serde_json::Map<String, Value>) -> Result<bool> {
        let Some(handle) = obj.get("n").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        let owner = obj.get("o").and_then(|v| v.as_str());
        let target = obj.get("u").and_then(|v| v.as_str());
        let pending = obj.get("p").and_then(|v| v.as_str());
        let access = obj.get("r").and_then(|v| v.as_i64());
        let ok_b64 = obj.get("ok").and_then(|v| v.as_str());
        let k_b64 = obj.get("k").and_then(|v| v.as_str());
        let _ha = obj.get("ha").and_then(|v| v.as_str());
        let _ts = obj.get("ts").and_then(|v| v.as_i64());
        let _op = obj.get("op").and_then(|v| v.as_i64());
        let _okd = obj.get("okd").and_then(|v| v.as_str());
        let ou = obj.get("ou").and_then(|v| v.as_str());

        let outbound = owner == Some(self.user_handle.as_str());
        let mut changed = false;
        // SDK parity: once ^!keys is active, outbound share APs carry dummy ok/ha values.
        // Do not ingest outbound share keys from action packets in secured mode.
        let ignore_outbound_share_key_material = outbound && self.key_manager.is_ready();

        let mut share_key: Option<[u8; 16]> = None;

        if outbound
            && !ignore_outbound_share_key_material
            && let Some(ok_str) = ok_b64
            && let Ok(enc) = base64url_decode(ok_str)
        {
            let dec = aes128_ecb_decrypt(&enc, &self.master_key);
            if dec.len() >= 16 {
                let mut key = [0u8; 16];
                key.copy_from_slice(&dec[..16]);
                // Defensive guard against dummy outbound key material.
                if key != [0u8; 16] {
                    share_key = Some(key);
                }
            }
        }

        if share_key.is_none()
            && !ignore_outbound_share_key_material
            && let Some(k_str) = k_b64
            && let Ok(enc) = base64url_decode(k_str)
        {
            if let Some(dec) = self.rsa_key().decrypt(&enc) {
                if dec.len() >= 16 {
                    let mut key = [0u8; 16];
                    key.copy_from_slice(&dec[..16]);
                    // Defensive guard against dummy outbound key material.
                    if !outbound || key != [0u8; 16] {
                        share_key = Some(key);
                    }
                }
            } else if !outbound
                && self.key_manager.is_ready()
                && let Some(owner_b64) = owner
                && let Some(owner_handle) = Self::decode_user_handle(owner_b64)
            {
                self.key_manager.add_pending_in(handle, &owner_handle, enc);
                changed = true;
            }
        }

        if let Some(key) = share_key {
            let in_use = access.is_none_or(|r| r >= 0);
            self.key_manager
                .add_share_key_with_flags(handle, &key, true, in_use);
            changed = true;
            // Update share metadata on the affected node.
            if let Some(node) = self.nodes.iter_mut().find(|n| n.handle == handle) {
                if outbound {
                    node.is_outshare = true;
                } else {
                    node.is_inshare = true;
                }
                if let Some(r) = access {
                    node.share_access = Some(r as i32);
                }
                if node.share_key.is_none() {
                    node.share_key = Some(key);
                }
            }
            self.drain_pending_nodes();
        }

        let sharee_id = pending.or(target);
        let is_removed = access.unwrap_or(-1) < 0;
        if outbound && let Some(id) = sharee_id {
            if is_removed {
                let total_before = self.outshare_total(handle);
                if self.remove_outshare(handle, id, pending.is_some()) {
                    changed = true;
                }
                if self.key_manager.is_ready()
                    && owner == Some(self.user_handle.as_str())
                    && ou != Some(self.user_handle.as_str())
                    && self.state_current
                    && self.key_manager.generation > 0
                    && self.key_manager.is_share_key_in_use(handle)
                    && total_before == 1
                    && self.key_manager.set_share_key_in_use(handle, false)
                {
                    changed = true;
                }
            } else if self.add_outshare(handle, id, pending.is_some()) {
                changed = true;
            }
        }

        if outbound && self.key_manager.is_ready() {
            let pending_id = sharee_id;
            if let Some(p) = pending_id {
                if p.contains('@') {
                    self.key_manager.add_pending_out_email(handle, p);
                    changed = true;
                } else if let Some(user_handle) = Self::decode_user_handle(p) {
                    self.key_manager
                        .add_pending_out_user_handle(handle, &user_handle);
                    changed = true;
                }
            }
        }

        if self.key_manager.is_ready()
            && let Some(r) = access
            && r >= 0
        {
            let mut flag_changed = false;
            flag_changed |= self.key_manager.set_share_key_in_use(handle, true);
            flag_changed |= self.key_manager.set_share_key_trusted(handle, true);
            if flag_changed {
                changed = true;
            }
        }

        Ok(changed)
    }

    fn handle_actionpacket_newnodes(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let nodes_array = if let Some(arr) = obj.get("t").and_then(|v| v.as_array()) {
            Some(arr)
        } else if let Some(tobj) = obj.get("t").and_then(|v| v.as_object()) {
            tobj.get("f").and_then(|v| v.as_array())
        } else {
            None
        };

        let Some(nodes_array) = nodes_array else {
            return Ok(false);
        };

        let mut changed = false;
        for node_json in nodes_array {
            if let Some(node) = self.try_parse_or_stash(node_json) {
                changed |= self.upsert_node(node);
            }
        }

        if changed {
            Self::build_node_paths(&mut self.nodes);
        }

        Ok(changed)
    }

    fn handle_actionpacket_update_node(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("n").and_then(|v| v.as_str()) else {
            return Ok(false);
        };
        let node_idx = match self.nodes.iter().position(|n| n.handle == handle) {
            Some(idx) => idx,
            None => return Ok(false),
        };

        let mut changed = false;
        if let Some(at) = obj.get("at").and_then(|v| v.as_str())
            && let Some(name) = self.decrypt_node_attrs(at, &self.nodes[node_idx].key)
            && self.nodes[node_idx].name != name
        {
            self.nodes[node_idx].name = name;
            changed = true;
        }

        if let Some(ts) = obj.get("ts").and_then(|v| v.as_i64())
            && self.nodes[node_idx].timestamp != ts
        {
            self.nodes[node_idx].timestamp = ts;
            changed = true;
        }

        if changed {
            Self::build_node_paths(&mut self.nodes);
        }

        Ok(changed)
    }

    fn handle_actionpacket_delete_node(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("n").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        let handle_map: HashMap<&str, usize> = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| (n.handle.as_str(), i))
            .collect();

        let mut remove = HashSet::new();
        for (i, node) in self.nodes.iter().enumerate() {
            if node.handle == handle
                || Self::node_has_ancestor_in_nodes(&self.nodes, i, handle, &handle_map)
            {
                remove.insert(node.handle.clone());
            }
        }

        if remove.is_empty() {
            return Ok(false);
        }

        self.nodes.retain(|n| !remove.contains(&n.handle));
        Self::build_node_paths(&mut self.nodes);
        Ok(true)
    }

    fn handle_actionpacket_public_link(
        &mut self,
        obj: &serde_json::Map<String, Value>,
    ) -> Result<bool> {
        let Some(handle) = obj.get("h").and_then(|v| v.as_str()) else {
            return Ok(false);
        };

        let deleted = obj.get("d").and_then(|v| v.as_i64()).unwrap_or(0) == 1;
        let link_handle = obj.get("ph").and_then(|v| v.as_str());

        for node in &mut self.nodes {
            if node.handle == handle {
                if deleted {
                    if node.link.is_some() {
                        node.link = None;
                        return Ok(true);
                    }
                    return Ok(false);
                }
                if let Some(ph) = link_handle
                    && node.link.as_deref() != Some(ph)
                {
                    node.link = Some(ph.to_string());
                    return Ok(true);
                }
                return Ok(false);
            }
        }

        Ok(false)
    }

    pub(crate) fn upsert_node(&mut self, node: Node) -> bool {
        if let Some(idx) = self.nodes.iter().position(|n| n.handle == node.handle) {
            self.nodes[idx] = node;
            true
        } else {
            self.nodes.push(node);
            true
        }
    }

    pub(crate) fn ingest_outshares_from_fetch(&mut self, s_array: &[Value]) {
        self.outshares.clear();
        self.pending_outshares.clear();

        for item in s_array {
            let Some(obj) = item.as_object() else {
                continue;
            };
            let Some(handle) = obj.get("h").and_then(|v| v.as_str()) else {
                continue;
            };
            let access = obj.get("r").and_then(|v| v.as_i64()).unwrap_or(-1);
            if access < 0 {
                continue;
            }
            if let Some(pending) = obj.get("p").and_then(|v| v.as_str()) {
                self.add_outshare(handle, pending, true);
                continue;
            }
            if let Some(user) = obj.get("u").and_then(|v| v.as_str()) {
                self.add_outshare(handle, user, false);
            }
        }
    }

    fn add_outshare(&mut self, handle: &str, sharee: &str, pending: bool) -> bool {
        let map = if pending {
            &mut self.pending_outshares
        } else {
            &mut self.outshares
        };
        let entry = map.entry(handle.to_string()).or_insert_with(HashSet::new);
        entry.insert(sharee.to_string())
    }

    fn remove_outshare(&mut self, handle: &str, sharee: &str, pending: bool) -> bool {
        let map = if pending {
            &mut self.pending_outshares
        } else {
            &mut self.outshares
        };
        let Some(entry) = map.get_mut(handle) else {
            return false;
        };
        let removed = entry.remove(sharee);
        if entry.is_empty() {
            map.remove(handle);
        }
        removed
    }

    fn outshare_total(&self, handle: &str) -> usize {
        let out_count = self.outshares.get(handle).map(|s| s.len()).unwrap_or(0);
        let pending_count = self
            .pending_outshares
            .get(handle)
            .map(|s| s.len())
            .unwrap_or(0);
        out_count + pending_count
    }

    pub(crate) fn cleanup_pending_outshares_for_deleted_contacts(&mut self) -> bool {
        let mut removed_any = false;
        for (_handle, sharees) in self.pending_outshares.iter_mut() {
            let before = sharees.len();
            sharees.retain(|sharee| {
                if sharee.contains('@') {
                    let still_exists = self
                        .contacts
                        .values()
                        .any(|c| c.email.as_deref() == Some(sharee));
                    return still_exists;
                }
                self.contacts.contains_key(sharee)
            });
            if sharees.len() != before {
                removed_any = true;
            }
        }

        if removed_any && self.key_manager.is_ready() {
            self.key_manager
                .pending_out
                .retain(|entry| match &entry.uid {
                    crate::crypto::key_manager::PendingUid::Email(email) => self
                        .contacts
                        .values()
                        .any(|c| c.email.as_deref() == Some(email)),
                    crate::crypto::key_manager::PendingUid::UserHandle(handle) => {
                        let handle_b64 = base64url_encode(handle);
                        self.contacts.contains_key(&handle_b64)
                    }
                });
        }
        removed_any
    }

    pub(crate) fn apply_deferred_share_packets(&mut self, packets: &[Value]) -> Result<bool> {
        let mut changed = false;
        for pkt in packets {
            let Some(obj) = pkt.as_object() else {
                continue;
            };
            let Some(action) = obj.get("a").and_then(|v| v.as_str()) else {
                continue;
            };
            if matches!(action, "s" | "s2") && self.handle_actionpacket_share(obj)? {
                changed = true;
            }
        }
        Ok(changed)
    }

    fn node_has_ancestor_in_nodes(
        nodes: &[Node],
        idx: usize,
        ancestor_handle: &str,
        handle_map: &HashMap<&str, usize>,
    ) -> bool {
        let mut current = nodes[idx].parent_handle.as_deref();
        for _ in 0..100 {
            match current {
                Some(handle) if handle == ancestor_handle => return true,
                Some(handle) => {
                    if let Some(&parent_idx) = handle_map.get(handle) {
                        current = nodes[parent_idx].parent_handle.as_deref();
                    } else {
                        return false;
                    }
                }
                None => return false,
            }
        }
        false
    }

    fn decode_user_handle(handle_b64: &str) -> Option<[u8; 8]> {
        let decoded = base64url_decode(handle_b64).ok()?;
        if decoded.len() != 8 {
            return None;
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&decoded);
        Some(out)
    }

    fn extract_contact_update(
        obj: &serde_json::Map<String, Value>,
    ) -> Result<Option<ActionPacketContactUpdate>> {
        let user = match obj.get("u").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => return Ok(None),
        };

        let cu_b64 = obj
            .get("prCu255")
            .or_else(|| obj.get("cu25519"))
            .or_else(|| obj.get("k"))
            .and_then(|v| v.as_str());
        let ed_b64 = obj
            .get("prEd255")
            .or_else(|| obj.get("ed25519"))
            .and_then(|v| v.as_str());

        let cu = cu_b64
            .map(base64url_decode)
            .transpose()?
            .filter(|v| !v.is_empty());
        let ed = ed_b64
            .map(base64url_decode)
            .transpose()?
            .filter(|v| !v.is_empty());
        let verified = obj.get("c").and_then(|v| v.as_i64()).unwrap_or(0) > 0;

        let email = obj.get("m").and_then(|v| v.as_str()).map(|s| s.to_string());
        let status = obj.get("c").and_then(|v| v.as_i64()).unwrap_or(0);
        let ts = obj.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
        let contact = Contact {
            handle: user.clone(),
            email,
            status,
            last_updated: ts,
        };

        if cu.is_none() && ed.is_none() {
            return Ok(Some((user, None, None, verified, Some(contact))));
        }

        Ok(Some((user, ed, cu, verified, Some(contact))))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::session::Session;

    #[tokio::test]
    async fn matching_action_packet_marks_current_seqtag_seen() {
        let mut session = Session::test_dummy();
        let _ = session.apply_request_seqtag(Some("seqtag-123".to_string()));

        let result = session
            .dispatch_action_packets(&[json!({"st": "seqtag-123"})])
            .await
            .expect("dispatch should succeed");

        assert!(!result.ap_pk_seen);
        assert!(!result.durable_tree_changed);
        assert!(!result.pending_keys_fetch);
        assert!(result.deferred_key_work.is_none());
        assert!(session.current_seqtag_seen);
    }
}
