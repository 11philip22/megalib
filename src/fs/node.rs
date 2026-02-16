//! Filesystem node types and operations.

use serde::{Deserialize, Serialize};

/// Node type enumeration matching MEGA's internal types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeType {
    /// Regular file
    File = 0,
    /// Folder/directory
    Folder = 1,
    /// Root folder (Cloud Drive)
    Root = 2,
    /// Inbox folder
    Inbox = 3,
    /// Trash folder
    Trash = 4,
    /// Contact node
    Contact = 8,
    /// Network/Contacts root
    Network = 9,
}

impl NodeType {
    /// Create from integer type value.
    pub fn from_i64(t: i64) -> Option<Self> {
        match t {
            0 => Some(NodeType::File),
            1 => Some(NodeType::Folder),
            2 => Some(NodeType::Root),
            3 => Some(NodeType::Inbox),
            4 => Some(NodeType::Trash),
            8 => Some(NodeType::Contact),
            9 => Some(NodeType::Network),
            _ => None,
        }
    }

    /// Check if this node type is a container (can have children).
    pub fn is_container(&self) -> bool {
        matches!(
            self,
            NodeType::Folder
                | NodeType::Root
                | NodeType::Inbox
                | NodeType::Trash
                | NodeType::Network
        )
    }
}

/// A node in the MEGA filesystem.
#[derive(Debug, Clone)]
pub struct Node {
    /// Node name (decrypted)
    pub name: String,
    /// Node handle (unique identifier)
    pub handle: String,
    /// Parent node handle
    pub parent_handle: Option<String>,
    /// Node type
    pub node_type: NodeType,
    /// File size in bytes (0 for folders)
    pub size: u64,
    /// Timestamp (Unix epoch)
    pub timestamp: i64,
    /// Decrypted node key
    pub(crate) key: Vec<u8>,
    /// Full path (computed after tree building)
    pub(crate) path: Option<String>,
    /// Public link handle (set by export)
    pub(crate) link: Option<String>,
    /// File attributes (fa)
    pub(crate) file_attr: Option<String>,
}

impl Node {
    /// Check if this node is a file.
    pub fn is_file(&self) -> bool {
        self.node_type == NodeType::File
    }

    /// Check if this node is a folder (any container type).
    pub fn is_folder(&self) -> bool {
        self.node_type.is_container()
    }

    /// Check if this node is a contact.
    pub fn is_contact(&self) -> bool {
        self.node_type == NodeType::Contact
    }

    /// Get the full path of this node.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Get the base64-encoded node key for public links.
    pub fn get_key(&self) -> Option<String> {
        if self.key.is_empty() {
            None
        } else {
            Some(crate::base64::base64url_encode(&self.key))
        }
    }

    /// Get the public download link (requires export to be called first).
    ///
    /// # Arguments
    /// * `include_key` - If true, includes the decryption key in the URL
    ///
    /// # Returns
    /// Full MEGA download URL if the node has been exported
    pub fn get_link(&self, include_key: bool) -> Option<String> {
        let link_handle = self.link.as_ref()?;

        if include_key {
            let key = self.get_key()?;
            Some(format!("https://mega.nz/file/{}#{}", link_handle, key))
        } else {
            Some(format!("https://mega.nz/file/{}", link_handle))
        }
    }

    /// Check if this node has been exported (has a public link).
    pub fn is_exported(&self) -> bool {
        self.link.is_some()
    }

    /// Check if this node is writable.
    ///
    /// For your own nodes, this always returns true. Nodes from shares
    /// may have restricted permissions, but the current implementation
    /// assumes all cached nodes are writable.
    ///
    /// # Returns
    /// `true` if the node can be modified
    pub fn is_writable(&self) -> bool {
        // For now, all user's own nodes are writable
        // In the future, this could check share permissions
        matches!(
            self.node_type,
            NodeType::File | NodeType::Folder | NodeType::Root | NodeType::Trash | NodeType::Inbox
        )
    }
}

/// User storage quota information.
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    /// Total storage in bytes
    pub total: u64,
    /// Used storage in bytes
    pub used: u64,
}

impl Quota {
    /// Get free storage in bytes.
    pub fn free(&self) -> u64 {
        self.total.saturating_sub(self.used)
    }

    /// Get usage percentage.
    pub fn usage_percent(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.used as f64 / self.total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_type_conversion() {
        assert_eq!(NodeType::from_i64(0), Some(NodeType::File));
        assert_eq!(NodeType::from_i64(1), Some(NodeType::Folder));
        assert_eq!(NodeType::from_i64(2), Some(NodeType::Root));
        assert_eq!(NodeType::from_i64(3), Some(NodeType::Inbox));
        assert_eq!(NodeType::from_i64(4), Some(NodeType::Trash));
        assert_eq!(NodeType::from_i64(8), Some(NodeType::Contact));
        assert_eq!(NodeType::from_i64(9), Some(NodeType::Network));
        assert_eq!(NodeType::from_i64(99), None);
    }

    #[test]
    fn test_node_type_properties() {
        assert!(!NodeType::File.is_container());
        assert!(NodeType::Folder.is_container());
        assert!(NodeType::Root.is_container());
        assert!(NodeType::Inbox.is_container());
        assert!(NodeType::Trash.is_container());
        assert!(NodeType::Network.is_container());
        assert!(!NodeType::Contact.is_container());
    }

    #[test]
    fn test_node_helper_methods() {
        let file_node = Node {
            name: "test.txt".to_string(),
            handle: "h1".to_string(),
            parent_handle: None,
            node_type: NodeType::File,
            size: 100,
            timestamp: 0,
            key: vec![],
            path: None,
            link: None,
            file_attr: None,
        };

        assert!(file_node.is_file());
        assert!(!file_node.is_folder());
        assert!(!file_node.is_contact());

        let folder_node = Node {
            name: "Folder".to_string(),
            handle: "h2".to_string(),
            parent_handle: None,
            node_type: NodeType::Folder,
            size: 0,
            timestamp: 0,
            key: vec![],
            path: None,
            link: None,
            file_attr: None,
        };

        assert!(!folder_node.is_file());
        assert!(folder_node.is_folder());
    }

    #[test]
    fn test_node_link_generation() {
        let node = Node {
            name: "test.txt".to_string(),
            handle: "h1".to_string(),
            parent_handle: None,
            node_type: NodeType::File,
            size: 100,
            timestamp: 0,
            key: vec![1, 2, 3, 4], // Fake key
            path: None,
            link: Some("LINK_HANDLE".to_string()),
            file_attr: None,
        };

        assert!(node.is_exported());

        let link_no_key = node.get_link(false).unwrap();
        assert_eq!(link_no_key, "https://mega.nz/file/LINK_HANDLE");

        let link_with_key = node.get_link(true).unwrap();
        assert!(link_with_key.contains("#"));
        assert!(link_with_key.contains("LINK_HANDLE"));
    }

    #[test]
    fn test_quota_calculations() {
        let quota = Quota {
            total: 1000,
            used: 250,
        };

        assert_eq!(quota.free(), 750);
        assert_eq!(quota.usage_percent(), 25.0);

        let empty_quota = Quota { total: 0, used: 0 };
        assert_eq!(empty_quota.usage_percent(), 0.0);
    }
}
