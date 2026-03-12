//! Filesystem browsing helpers.

use super::utils::normalize_path;
use crate::error::Result;
use crate::fs::node::{Node, NodeType};
use crate::session::Session;

impl Session {
    /// Return the Cloud Drive root, Inbox, Trash, and Network nodes.
    pub fn root_nodes(&self) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| {
                matches!(
                    n.node_type,
                    NodeType::Root | NodeType::Inbox | NodeType::Trash | NodeType::Network
                )
            })
            .collect()
    }

    /// List files in a directory.
    ///
    /// # Arguments
    /// * `path` - The path to list (e.g., "/Root", "/Root/Documents")
    /// * `recursive` - If true, list all descendants recursively
    ///
    /// The Cloud Drive root is `/Root`.
    ///
    /// # Returns
    /// Vector of nodes matching the path
    pub fn list(&self, path: &str, recursive: bool) -> Result<Vec<&Node>> {
        let normalized_path = normalize_path(path);
        let search_prefix = if normalized_path == "/" {
            "/".to_string()
        } else {
            format!("{}/", normalized_path)
        };

        let mut results = Vec::new();

        for node in &self.nodes {
            if let Some(node_path) = &node.path {
                if recursive {
                    // Include all nodes under this path
                    if node_path.starts_with(&search_prefix) && node_path != &normalized_path {
                        results.push(node);
                    }
                } else {
                    // Include only direct children
                    if let Some(stripped) = node_path.strip_prefix(&search_prefix)
                        && !stripped.contains('/')
                        && !stripped.is_empty()
                    {
                        results.push(node);
                    }
                }
            }
        }

        Ok(results)
    }

    /// List all contacts.
    ///
    /// Returns all nodes of type Contact. Contacts are users who have
    /// interacted with your shared files or folders.
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::SessionHandle;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// for contact in session.list_contacts().await? {
    ///     println!("Contact: {}", contact.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn list_contacts(&self) -> Vec<&Node> {
        self.nodes.iter().filter(|n| n.is_contact()).collect()
    }

    /// Get information about a file or folder.
    ///
    /// # Arguments
    /// * `path` - The path to stat
    ///
    /// # Returns
    /// Node information if found
    pub fn stat(&self, path: &str) -> Option<&Node> {
        let normalized_path = normalize_path(path);

        self.nodes
            .iter()
            .find(|n| n.path.as_deref() == Some(&normalized_path))
    }

    /// Get a node by its handle.
    ///
    /// # Arguments
    /// * `handle` - The node handle (e.g., "ABC123xyz")
    ///
    /// # Returns
    /// Node reference if found
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::SessionHandle;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// if let Some(node) = session.get_node_by_handle("ABC123").await? {
    ///     println!("Found: {}", node.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_node_by_handle(&self, handle: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.handle == handle)
    }

    /// Return the direct children of a node handle from the cached tree.
    pub fn children_by_handle(&self, parent_handle: &str) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| n.parent_handle.as_deref() == Some(parent_handle))
            .collect()
    }

    /// Return the direct children of a cached node.
    pub fn children(&self, parent: &Node) -> Vec<&Node> {
        self.children_by_handle(&parent.handle)
    }

    /// Return a direct child of a node handle by name.
    pub fn child_node_by_name_handle(&self, parent_handle: &str, name: &str) -> Option<&Node> {
        self.children_by_handle(parent_handle)
            .into_iter()
            .find(|node| node.name == name)
    }

    /// Return a direct child of a cached node by name.
    pub fn child_node_by_name(&self, parent: &Node, name: &str) -> Option<&Node> {
        self.child_node_by_name_handle(&parent.handle, name)
    }

    /// Return a direct child of a node handle by name and type.
    pub fn child_node_by_name_type_handle(
        &self,
        parent_handle: &str,
        name: &str,
        node_type: NodeType,
    ) -> Option<&Node> {
        self.children_by_handle(parent_handle)
            .into_iter()
            .find(|node| node.name == name && node.node_type == node_type)
    }

    /// Return a direct child of a cached node by name and type.
    pub fn child_node_by_name_type(
        &self,
        parent: &Node,
        name: &str,
        node_type: NodeType,
    ) -> Option<&Node> {
        self.child_node_by_name_type_handle(&parent.handle, name, node_type)
    }

    /// Return all descendants of a node handle from the cached tree.
    pub fn descendants_by_handle(&self, parent_handle: &str) -> Vec<&Node> {
        let Some(parent) = self.get_node_by_handle(parent_handle) else {
            return Vec::new();
        };

        self.nodes
            .iter()
            .filter(|n| n.handle != parent.handle && self.node_has_ancestor(n, parent))
            .collect()
    }

    /// Return all descendants of a cached node.
    pub fn descendants(&self, parent: &Node) -> Vec<&Node> {
        self.descendants_by_handle(&parent.handle)
    }

    /// Check if a node has a specific ancestor.
    ///
    /// This walks up the parent chain to check if `ancestor` is in
    /// the path from `node` to the root.
    ///
    /// # Arguments
    /// * `node` - The node to check
    /// * `ancestor` - The potential ancestor node
    ///
    /// # Returns
    /// `true` if `ancestor` is in `node`'s parent chain
    ///
    /// # Example
    /// ```no_run
    /// # use megalib::SessionHandle;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let file = session.stat("/Root/Documents/file.txt").await?.unwrap();
    /// let folder = session.stat("/Root/Documents").await?.unwrap();
    /// assert!(session.node_has_ancestor(&file, &folder).await?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn node_has_ancestor(&self, node: &Node, ancestor: &Node) -> bool {
        let mut current_handle = node.parent_handle.as_ref();

        // Walk up the tree (max 100 levels to prevent infinite loops)
        for _ in 0..100 {
            match current_handle {
                Some(handle) if handle == &ancestor.handle => return true,
                Some(handle) => {
                    if let Some(parent) = self.get_node_by_handle(handle) {
                        current_handle = parent.parent_handle.as_ref();
                    } else {
                        return false;
                    }
                }
                None => return false,
            }
        }
        false
    }

    /// Return all inbound share root nodes.
    ///
    /// Mirrors the C++ SDK's `NodeManager::getNodesWithInShares`.
    pub fn nodes_with_inshares(&self) -> Vec<&Node> {
        self.nodes.iter().filter(|n| n.is_inshare).collect()
    }

    /// Return all outbound share root nodes.
    ///
    /// Mirrors the C++ SDK's `NodeManager::getNodesWithOutShares`.
    pub fn nodes_with_outshares(&self) -> Vec<&Node> {
        self.nodes.iter().filter(|n| n.is_outshare).collect()
    }

    /// Return nodes with pending outgoing shares (not yet accepted/confirmed).
    ///
    /// Mirrors the C++ SDK's `NodeManager::getNodesWithPendingOutShares`.
    pub fn nodes_with_pending_outshares(&self) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| self.pending_outshares.contains_key(&n.handle))
            .collect()
    }

    /// Return the Cloud Drive root, Inbox, Trash, and all inbound share roots.
    ///
    /// Mirrors the C++ SDK's `NodeManager::getRootNodesAndInshares`.
    pub fn root_nodes_and_inshares(&self) -> Vec<&Node> {
        self.nodes
            .iter()
            .filter(|n| {
                matches!(
                    n.node_type,
                    NodeType::Root | NodeType::Inbox | NodeType::Trash
                ) || n.is_inshare
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::fs::{Node, NodeType};
    use crate::session::Session;

    fn node(name: &str, handle: &str, parent_handle: Option<&str>, node_type: NodeType) -> Node {
        Node {
            name: name.to_string(),
            handle: handle.to_string(),
            parent_handle: parent_handle.map(ToString::to_string),
            node_type,
            size: 0,
            timestamp: 0,
            key: vec![],
            path: None,
            link: None,
            file_attr: None,
            share_key: None,
            share_handle: None,
            is_inshare: false,
            is_outshare: false,
            share_access: None,
        }
    }

    #[test]
    fn root_nodes_returns_system_roots_only() {
        let mut session = Session::test_dummy();
        session.nodes = vec![
            node("Root", "root", None, NodeType::Root),
            node("Inbox", "inbox", None, NodeType::Inbox),
            node("Trash", "trash", None, NodeType::Trash),
            node("Network", "network", None, NodeType::Network),
            node("Docs", "docs", Some("root"), NodeType::Folder),
        ];

        let handles: Vec<&str> = session
            .root_nodes()
            .into_iter()
            .map(|n| n.handle.as_str())
            .collect();
        assert_eq!(handles, vec!["root", "inbox", "trash", "network"]);
    }

    #[test]
    fn children_lookup_uses_parent_handle() {
        let mut session = Session::test_dummy();
        session.nodes = vec![
            node("Root", "root", None, NodeType::Root),
            node("Docs", "docs", Some("root"), NodeType::Folder),
            node("Photos", "photos", Some("root"), NodeType::Folder),
            node("Nested", "nested", Some("docs"), NodeType::Folder),
        ];

        let root = session.get_node_by_handle("root").unwrap().clone();
        let child_handles: Vec<&str> = session
            .children(&root)
            .into_iter()
            .map(|n| n.handle.as_str())
            .collect();
        let nested_handles: Vec<&str> = session
            .children_by_handle("docs")
            .into_iter()
            .map(|n| n.handle.as_str())
            .collect();

        assert_eq!(child_handles, vec!["docs", "photos"]);
        assert_eq!(nested_handles, vec!["nested"]);
    }

    #[test]
    fn descendants_walk_entire_subtree() {
        let mut session = Session::test_dummy();
        session.nodes = vec![
            node("Root", "root", None, NodeType::Root),
            node("Docs", "docs", Some("root"), NodeType::Folder),
            node("Nested", "nested", Some("docs"), NodeType::Folder),
            node("Deep", "deep", Some("nested"), NodeType::Folder),
            node("notes.txt", "file", Some("docs"), NodeType::File),
            node("deep.txt", "deep-file", Some("deep"), NodeType::File),
        ];

        let docs = session.get_node_by_handle("docs").unwrap().clone();
        let descendant_handles: Vec<&str> = session
            .descendants(&docs)
            .into_iter()
            .map(|n| n.handle.as_str())
            .collect();

        assert_eq!(
            descendant_handles,
            vec!["nested", "deep", "file", "deep-file"]
        );
    }

    #[test]
    fn child_lookup_by_name_and_type_uses_cached_parent() {
        let mut session = Session::test_dummy();
        session.nodes = vec![
            node("Root", "root", None, NodeType::Root),
            node("Docs", "docs-folder", Some("root"), NodeType::Folder),
            node("Docs", "docs-file", Some("root"), NodeType::File),
            node("Other", "other", Some("root"), NodeType::Folder),
        ];

        let root = session.get_node_by_handle("root").unwrap().clone();

        let by_name = session.child_node_by_name(&root, "Docs").unwrap();
        let by_name_type = session
            .child_node_by_name_type(&root, "Docs", NodeType::Folder)
            .unwrap();
        let by_name_type_handle = session
            .child_node_by_name_type_handle("root", "Docs", NodeType::File)
            .unwrap();

        assert_eq!(by_name.handle, "docs-folder");
        assert_eq!(by_name_type.handle, "docs-folder");
        assert_eq!(by_name_type_handle.handle, "docs-file");
    }
}
