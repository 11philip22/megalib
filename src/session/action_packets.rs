//! Action packet handling for Session.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::time::timeout;

use crate::base64::{base64url_decode, base64url_encode};
use crate::crypto::aes::aes128_ecb_decrypt;
use crate::error::{MegaError, Result};
use crate::fs::Node;
use crate::session::session::Contact;
use crate::session::Session;

impl Session {
    /// Poll the SC channel once and dispatch action packets.
    ///
    /// Returns true if any local state changed (e.g., ^!keys or authrings updated).
    /// This is legacy; prefer the Session actor which polls in the background.
    pub(crate) async fn poll_action_packets_once(&mut self) -> Result<bool> {
        let (changed, _) = self.poll_action_packets_once_with_seqtags().await?;
        Ok(changed)
    }

    pub(crate) async fn poll_action_packets_once_with_seqtags(
        &mut self,
    ) -> Result<(bool, Vec<String>)> {
        if self.scsn.is_none() {
            return Err(MegaError::Custom(
                "SC not initialized; call refresh() before polling action packets".to_string(),
            ));
        }
        let mut changed = false;
        let mut seqtags = Vec::new();
        loop {
            let (packets, sn, wsc, ir) = self
                .api
                .poll_sc(
                    self.scsn.as_deref(),
                    self.wsc_url.as_deref(),
                    self.sc_catchup,
                )
                .await?;
            self.scsn = Some(sn);
            if let Some(w) = wsc {
                self.wsc_url = Some(w);
            }
            seqtags.extend(Self::extract_seqtags_from_packets(&packets));
            if self.dispatch_action_packets(&packets).await? {
                changed = true;
            }
            if !ir {
                if self.sc_catchup {
                    self.sc_catchup = false;
                }
                break;
            }
        }
        Ok((changed, seqtags))
    }

    fn extract_seqtags_from_packets(packets: &[Value]) -> Vec<String> {
        let mut out = Vec::new();
        for pkt in packets {
            if let Some(obj) = pkt.as_object() {
                if let Some(st) = obj.get("st").and_then(|v| v.as_str()) {
                    out.push(st.to_string());
                }
            }
        }
        out
    }

    fn extract_seqtag_from_response(response: &Value) -> Option<String> {
        if let Some(st) = response.get("st").and_then(|v| v.as_str()) {
            return Some(st.to_string());
        }
        if let Some(arr) = response.as_array() {
            if let Some(st) = arr.get(0).and_then(|v| v.as_str()) {
                return Some(st.to_string());
            }
        }
        None
    }

    pub(crate) fn track_seqtag_from_response(&mut self, response: &Value) -> Option<String> {
        let st = Self::extract_seqtag_from_response(response)?;
        self.current_seqtag = Some(st.clone());
        self.current_seqtag_seen = false;
        Some(st)
    }

    pub(crate) async fn wait_for_seqtag(&mut self, expected: &str) -> Result<()> {
        if self.scsn.is_none() {
            return Err(MegaError::Custom(
                "SC not initialized; call refresh() before waiting for action packets".to_string(),
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.current_seqtag_seen && self.current_seqtag.as_deref() == Some(expected) {
                self.current_seqtag = None;
                self.current_seqtag_seen = false;
                return Ok(());
            }

            match timeout(Duration::from_secs(20), self.poll_action_packets_once()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    // Ignore long-poll timeout; try again until deadline.
                }
            }
        }

        Err(MegaError::Custom(
            "Timed out waiting for action packets".to_string(),
        ))
    }

    /// Poll user alerts (SC50) once. Optional, used by clients that need alerts.
    pub async fn poll_user_alerts_once(&mut self) -> Result<(Vec<Value>, Option<String>)> {
        if self.scsn.is_none() {
            return Ok((Vec::new(), self.user_alert_lsn.clone()));
        }
        let (alerts, lsn) = self.api.poll_user_alerts().await?;
        if !alerts.is_empty() {
            self.user_alerts.extend(alerts.clone());
        }
        if let Some(token) = lsn.clone() {
            self.user_alert_lsn = Some(token);
        }
        self.alerts_catchup_pending = false;
        Ok((alerts, lsn))
    }

    // /// Run a lightweight action-packet loop with exponential backoff.
    // ///
    // /// The `should_stop` predicate is evaluated after each poll to allow
    // /// embedding applications to terminate the loop.
    // pub(crate) async fn run_action_packet_loop<F>(&mut self, mut should_stop: F) -> Result<()>
    // where
    //     F: FnMut() -> bool,
    // {
    //     let mut delay_ms = 1_000u64;
    //     let max_delay = 60_000u64;

    //     while !should_stop() {
    //         match self.poll_action_packets_once().await {
    //             Ok(_) => {
    //                 delay_ms = 1_000;
    //             }
    //             Err(MegaError::ServerBusy) | Err(MegaError::InvalidResponse) => {
    //                 delay_ms = (delay_ms * 2).min(max_delay);
    //             }
    //             Err(e) => return Err(e),
    //         }
    //         sleep(Duration::from_millis(delay_ms)).await;
    //     }
    //     Ok(())
    // }

    async fn dispatch_action_packets(&mut self, packets: &[Value]) -> Result<bool> {
        let mut changed_handles = Vec::new();
        let mut contact_updates = Vec::new();
        let mut node_changed = false;
        let mut share_changed = false;
        let mut key_event = false;
        let mut stale_user_attrs = HashSet::new();

        for pkt in packets {
            if let Some(obj) = pkt.as_object() {
                if let Some(st) = obj.get("st").and_then(|v| v.as_str()) {
                    if self.current_seqtag.as_deref() == Some(st) {
                        self.current_seqtag_seen = true;
                    }
                }

                if let Some(origin) = obj.get("i").and_then(|v| v.as_str()) {
                    if origin == self.session_id() {
                        let action = obj.get("a").and_then(|v| v.as_str());
                        if !matches!(action, Some("d") | Some("t")) {
                            continue;
                        }
                    }
                }

                Self::extract_handles_from_action(obj, &mut changed_handles);
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
                if self.handle_actionpacket_nodes(obj)? {
                    if is_share_action {
                        share_changed = true;
                    } else {
                        node_changed = true;
                    }
                }
            }
        }

        let mut changed = false;
        if !contact_updates.is_empty() {
            let mut contact_changed = false;
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
                        contact_changed = true;
                    }
                }
            }
            if self.handle_contact_updates(&contact_updates).await? {
                changed = true;
            }
            if contact_changed {
                changed = true;
                if self.key_manager.is_ready() {
                    self.cleanup_pending_outshares_for_deleted_contacts();
                }
            }
            self.maybe_clear_cv_warning();
        }

        if !stale_user_attrs.is_empty() {
            let key_attrs_changed = stale_user_attrs.iter().any(|attr| Self::is_key_attr(attr));
            if self.refetch_user_attrs(&stale_user_attrs).await? {
                changed = true;
            }
            if key_attrs_changed {
                key_event = true;
            }
        }

        if share_changed {
            key_event = true;
        }

        if key_event || !changed_handles.is_empty() || share_changed {
            if self
                .handle_actionpacket_keys(&changed_handles, share_changed)
                .await?
            {
                changed = true;
            }
        }

        if share_changed && !self.key_manager.is_ready() {
            changed = true;
        }

        if node_changed {
            changed = true;
        }

        Ok(changed)
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

    async fn refetch_user_attrs(&mut self, stale: &HashSet<String>) -> Result<bool> {
        let priority = [
            "^!keys",
            "*keyring",
            "*~usk",
            "*~jscd",
            "+puCu255",
            "+puEd255",
            "+sigCu255",
            "+sigPubk",
        ];

        let mut changed = false;
        for attr in priority {
            if !stale.contains(attr) {
                continue;
            }
            let existing = self.user_attr_cache.get(attr).cloned();
            let fetched = self.get_user_attribute_raw(attr).await?;
            if fetched.is_some() {
                changed = true;
            } else if existing.is_some() {
                self.user_attr_cache.remove(attr);
                self.user_attr_versions.remove(attr);
                changed = true;
            }
        }
        Ok(changed)
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

        let mut share_key: Option<[u8; 16]> = None;

        if outbound {
            if let Some(ok_str) = ok_b64 {
                if let Ok(enc) = base64url_decode(ok_str) {
                    let dec = aes128_ecb_decrypt(&enc, &self.master_key);
                    if dec.len() >= 16 {
                        let mut key = [0u8; 16];
                        key.copy_from_slice(&dec[..16]);
                        share_key = Some(key);
                    }
                }
            }
        }

        if share_key.is_none() {
            if let Some(k_str) = k_b64 {
                if let Ok(enc) = base64url_decode(k_str) {
                    if let Some(dec) = self.rsa_key().decrypt(&enc) {
                        if dec.len() >= 16 {
                            let mut key = [0u8; 16];
                            key.copy_from_slice(&dec[..16]);
                            share_key = Some(key);
                        }
                    } else if !outbound && self.key_manager.is_ready() {
                        if let Some(owner_b64) = owner {
                            if let Some(owner_handle) = Self::decode_user_handle(owner_b64) {
                                self.key_manager.add_pending_in(handle, &owner_handle, enc);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }

        if let Some(key) = share_key {
            self.share_keys.insert(handle.to_string(), key);
            changed = true;
            if self.key_manager.is_ready() {
                let in_use = access.map_or(true, |r| r >= 0);
                self.key_manager
                    .add_share_key_with_flags(handle, &key, true, in_use);
            }
        }

        let sharee_id = pending.or(target);
        let is_removed = access.unwrap_or(-1) < 0;
        if outbound {
            if let Some(id) = sharee_id {
                if is_removed {
                    let total_before = self.outshare_total(handle);
                    if self.remove_outshare(handle, id, pending.is_some()) {
                        changed = true;
                    }
                    if self.key_manager.is_ready()
                        && owner == Some(self.user_handle.as_str())
                        && ou.as_deref() != Some(self.user_handle.as_str())
                        && !self.sc_catchup
                        && self.key_manager.generation > 0
                        && self.key_manager.is_share_key_in_use(handle)
                        && total_before == 1
                    {
                        if self.key_manager.set_share_key_in_use(handle, false) {
                            changed = true;
                        }
                    }
                } else if self.add_outshare(handle, id, pending.is_some()) {
                    changed = true;
                }
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

        if self.key_manager.is_ready() {
            if let Some(r) = access {
                if r >= 0 {
                    let mut flag_changed = false;
                    flag_changed |= self.key_manager.set_share_key_in_use(handle, true);
                    flag_changed |= self.key_manager.set_share_key_trusted(handle, true);
                    if flag_changed {
                        changed = true;
                    }
                }
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
            if let Some(node) = self.parse_node(node_json) {
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
        if let Some(at) = obj.get("at").and_then(|v| v.as_str()) {
            if let Some(name) = self.decrypt_node_attrs(at, &self.nodes[node_idx].key) {
                if self.nodes[node_idx].name != name {
                    self.nodes[node_idx].name = name;
                    changed = true;
                }
            }
        }

        if let Some(ts) = obj.get("ts").and_then(|v| v.as_i64()) {
            if self.nodes[node_idx].timestamp != ts {
                self.nodes[node_idx].timestamp = ts;
                changed = true;
            }
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
                if let Some(ph) = link_handle {
                    if node.link.as_deref() != Some(ph) {
                        node.link = Some(ph.to_string());
                        return Ok(true);
                    }
                }
                return Ok(false);
            }
        }

        Ok(false)
    }

    fn upsert_node(&mut self, node: Node) -> bool {
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

    fn cleanup_pending_outshares_for_deleted_contacts(&mut self) {
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
            if sharees.is_empty() && before > 0 {
                removed_any = true;
            } else if sharees.len() != before {
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
    ) -> Result<
        Option<(
            String,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
            bool,
            Option<Contact>,
        )>,
    > {
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
