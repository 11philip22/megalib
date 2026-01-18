//! Filesystem browsing helpers.

use crate::error::Result;
use crate::fs::node::Node;
use crate::session::Session;
use super::utils::normalize_path;

impl Session {
    /// List files in a directory.
    ///
    /// # Arguments
    /// * `path` - The path to list (e.g., "/", "/Documents")
    /// * `recursive` - If true, list all descendants recursively
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
                    if node_path.starts_with(&search_prefix) || node_path == &normalized_path {
                        if node_path != &normalized_path {
                            results.push(node);
                        }
                    }
                } else {
                    // Include only direct children
                    if let Some(stripped) = node_path.strip_prefix(&search_prefix) {
                        if !stripped.contains('/') && !stripped.is_empty() {
                            results.push(node);
                        }
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
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// for contact in session.list_contacts() {
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
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// if let Some(node) = session.get_node_by_handle("ABC123") {
    ///     println!("Found: {}", node.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_node_by_handle(&self, handle: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.handle == handle)
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
    /// # use megalib::Session;
    /// # async fn example() -> megalib::error::Result<()> {
    /// let mut session = Session::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let file = session.stat("/Root/Documents/file.txt").unwrap();
    /// let folder = session.stat("/Root/Documents").unwrap();
    /// assert!(session.node_has_ancestor(file, folder));
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

}
