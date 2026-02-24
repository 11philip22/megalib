//! Actor-based session runtime for background SC polling.

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures::io::{AsyncRead, AsyncSeek};
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, oneshot};
use tracing::debug;

use crate::crypto::{AuthState, Warnings};
use crate::error::{MegaError, Result};
use crate::fs::{Node, Quota};
use crate::progress::ProgressCallback;
use crate::session::core::{FolderSessionBlob, Session, SessionBlob};
use crate::session::key_sync::ActionPacketKeyWork;
use crate::session::sc_poller::{ScPoller, ScPollerControl, ScPollerEvent, ScPollerState};

trait AsyncReadSeek: AsyncRead + AsyncSeek + Unpin + Send {}

impl<T> AsyncReadSeek for T where T: AsyncRead + AsyncSeek + Unpin + Send {}

type BoxedReader = Box<dyn AsyncReadSeek>;
type BoxedWriter = Box<dyn Write + Send>;
type SeqtagWaiter = Box<dyn FnOnce(&mut Session) + Send>;

enum DeferredKeyWork {
    FromActionPacket {
        work: ActionPacketKeyWork,
        attempts: u8,
        ready_at: Instant,
    },
    PendingKeysFetch {
        attempts: u8,
        ready_at: Instant,
    },
    StartupReconciliation {
        attempts: u8,
        ready_at: Instant,
    },
}

const MAX_DEFERRED_KEY_WORK_RETRIES: u8 = 3;
const MAX_DEFERRED_KEY_WORK_QUEUE: usize = 64;
const DEFERRED_KEY_WORK_POLL_INTERVAL: Duration = Duration::from_millis(100);

impl DeferredKeyWork {
    fn is_due(&self, now: Instant) -> bool {
        match self {
            DeferredKeyWork::FromActionPacket { ready_at, .. }
            | DeferredKeyWork::PendingKeysFetch { ready_at, .. }
            | DeferredKeyWork::StartupReconciliation { ready_at, .. } => *ready_at <= now,
        }
    }
}

/// Account metadata for the current session.
///
/// Returned by [`SessionHandle::account_info`], this captures the server-reported
/// identity and the active session id.
#[derive(Debug, Clone)]
pub struct AccountInfo {
    /// Account email address.
    pub email: String,
    /// Display name, if set.
    pub name: Option<String>,
    /// User handle (base64url).
    pub user_handle: String,
    /// Active session identifier.
    pub session_id: String,
}

/// Handle to a background MEGA session actor.
///
/// This type is cheap to clone and forwards requests to a task that maintains
/// session state and polling.
///
/// # Examples
/// ```no_run
/// use megalib::SessionHandle;
///
/// # async fn example() -> megalib::Result<()> {
/// let session = SessionHandle::login("user@example.com", "password").await?;
/// # let _ = session;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct SessionHandle {
    tx: mpsc::Sender<SessionCommand>,
}

enum SessionCommand {
    AccountInfo {
        reply: oneshot::Sender<Result<AccountInfo>>,
    },
    DumpSession {
        reply: oneshot::Sender<Result<String>>,
    },
    DumpSessionBlob {
        reply: oneshot::Sender<Result<Vec<u8>>>,
    },
    Refresh {
        reply: oneshot::Sender<Result<()>>,
    },
    Quota {
        reply: oneshot::Sender<Result<Quota>>,
    },
    List {
        path: String,
        recursive: bool,
        reply: oneshot::Sender<Result<Vec<Node>>>,
    },
    Stat {
        path: String,
        reply: oneshot::Sender<Result<Option<Node>>>,
    },
    Nodes {
        reply: oneshot::Sender<Result<Vec<Node>>>,
    },
    ListContacts {
        reply: oneshot::Sender<Result<Vec<Node>>>,
    },
    GetNodeByHandle {
        handle: String,
        reply: oneshot::Sender<Result<Option<Node>>>,
    },
    NodeHasAncestor {
        node_handle: String,
        ancestor_handle: String,
        reply: oneshot::Sender<Result<bool>>,
    },
    Mkdir {
        path: String,
        reply: oneshot::Sender<Result<Node>>,
    },
    Mv {
        source: String,
        dest: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Rename {
        path: String,
        new_name: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Rm {
        path: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Export {
        path: String,
        reply: oneshot::Sender<Result<String>>,
    },
    ExportMany {
        paths: Vec<String>,
        reply: oneshot::Sender<Result<Vec<(String, String)>>>,
    },
    ShareFolder {
        handle: String,
        email: String,
        level: i32,
        reply: oneshot::Sender<Result<()>>,
    },
    Upload {
        local: String,
        remote: String,
        reply: oneshot::Sender<Result<Node>>,
    },
    UploadFromBytes {
        data: Vec<u8>,
        filename: String,
        remote: String,
        reply: oneshot::Sender<Result<Node>>,
    },
    UploadFromReader {
        reader: BoxedReader,
        filename: String,
        size: u64,
        remote: String,
        reply: oneshot::Sender<Result<Node>>,
    },
    UploadResumable {
        local: String,
        remote_parent: String,
        reply: oneshot::Sender<Result<Node>>,
    },
    DownloadToFile {
        node: Node,
        path: PathBuf,
        reply: oneshot::Sender<Result<()>>,
    },
    DownloadToWriter {
        node: Node,
        writer: BoxedWriter,
        offset: u64,
        reply: oneshot::Sender<Result<()>>,
    },
    SetWorkers {
        workers: usize,
        reply: oneshot::Sender<Result<()>>,
    },
    SetResume {
        enabled: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    ClearStatus {
        reply: oneshot::Sender<Result<()>>,
    },
    EnablePreviews {
        enabled: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    SetAuthringEd25519 {
        blob: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    SetAuthringCu25519 {
        blob: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    SetBackupsBlob {
        blob: Vec<u8>,
        reply: oneshot::Sender<Result<()>>,
    },
    SetWarnings {
        warnings: Warnings,
        reply: oneshot::Sender<Result<()>>,
    },
    SetContactVerificationWarning {
        enabled: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    SetManualVerification {
        enabled: bool,
        reply: oneshot::Sender<Result<()>>,
    },
    KeysDowngradeDetected {
        reply: oneshot::Sender<Result<bool>>,
    },
    ContactVerificationWarning {
        reply: oneshot::Sender<Result<bool>>,
    },
    AuthringState {
        handle: String,
        reply: oneshot::Sender<Result<(Option<AuthState>, Option<AuthState>)>>,
    },
    WatchStatus {
        callback: ProgressCallback,
        reply: oneshot::Sender<Result<()>>,
    },
    ChangePassword {
        new_password: String,
        reply: oneshot::Sender<Result<()>>,
    },
    Save {
        path: PathBuf,
        reply: oneshot::Sender<Result<()>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

struct SessionActor {
    session: Session,
    rx: mpsc::Receiver<SessionCommand>,
    sc_event_rx: mpsc::Receiver<ScPollerEvent>,
    sc_control_tx: mpsc::Sender<ScPollerControl>,
    sc_poller_task: Option<tokio::task::JoinHandle<()>>,
    seqtag_waiters: HashMap<String, Vec<SeqtagWaiter>>,
    key_work_queue: VecDeque<DeferredKeyWork>,
    deferred_key_work_enqueued: u64,
    deferred_key_work_coalesced: u64,
    deferred_key_work_started: u64,
    deferred_key_work_retried: u64,
    deferred_key_work_dropped: u64,
    deferred_key_work_queue_hwm: usize,
    ap_pk_seen: u64,
    pending_keys_fetch_queued: u64,
    pending_keys_fetch_started: u64,
    state_current_transitions: u64,
    action_packets_current_transitions: u64,
    deferred_pk_bursts: u64,
    startup_reconciliation_requested: bool,
    startup_reconciliation_queued: bool,
    startup_reconciliation_enqueued: u64,
    startup_reconciliation_started: u64,
    startup_reconciliation_completed: u64,
    startup_reconciliation_retried: u64,
    startup_reconciliation_dropped: u64,
    last_key_generation: u32,
    persist_requested: u64,
    persist_started: u64,
    persist_coalesced: u64,
}

impl SessionHandle {
    /// Parse a base64-encoded session blob.
    ///
    /// Use this to inspect or persist SDK-compatible session blobs without creating
    /// a live session.
    ///
    /// # Errors
    /// Returns an error if the blob is malformed or uses an unsupported format.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # fn example() -> megalib::Result<()> {
    /// let blob = "BASE64_BLOB";
    /// let parsed = SessionHandle::parse_session_blob(blob)?;
    /// # let _ = parsed;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_session_blob(session_b64: &str) -> Result<SessionBlob> {
        Session::parse_session_blob(session_b64)
    }

    /// Parse a base64-encoded folder session blob.
    ///
    /// This is used for SDK-compatible public folder sessions.
    ///
    /// # Errors
    /// Returns an error if the blob is malformed or uses an unsupported format.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # fn example() -> megalib::Result<()> {
    /// let blob = "BASE64_BLOB";
    /// let parsed = SessionHandle::parse_folder_session_blob(blob)?;
    /// # let _ = parsed;
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_folder_session_blob(session_b64: &str) -> Result<FolderSessionBlob> {
        Session::parse_folder_session_blob(session_b64)
    }

    /// Serialize a folder session blob into its base64 form.
    ///
    /// This is the inverse of [`SessionHandle::parse_folder_session_blob`].
    ///
    /// # Errors
    /// Returns an error if the blob cannot be encoded.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::{SessionHandle, FolderSessionBlob};
    ///
    /// # fn example(blob: &FolderSessionBlob) -> megalib::Result<()> {
    /// let encoded = SessionHandle::dump_folder_session_blob(blob)?;
    /// # let _ = encoded;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dump_folder_session_blob(blob: &FolderSessionBlob) -> Result<String> {
        Session::dump_folder_session_blob(blob)
    }

    /// Log in with an email address and password.
    ///
    /// On success this spawns a background actor for polling and returns a
    /// [`SessionHandle`].
    ///
    /// # Errors
    /// Returns an error if authentication or network requests fail.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// # let _ = session;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login(email: &str, password: &str) -> Result<Self> {
        let session = Session::login(email, password).await?;
        Ok(SessionActor::spawn(session))
    }

    /// Log in using an HTTP/SOCKS proxy.
    ///
    /// The proxy string is passed through to the underlying HTTP client.
    ///
    /// # Errors
    /// Returns an error if the proxy is invalid or authentication fails.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login_with_proxy(
    ///     "user@example.com",
    ///     "password",
    ///     "http://proxy:8080",
    /// ).await?;
    /// # let _ = session;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login_with_proxy(email: &str, password: &str, proxy: &str) -> Result<Self> {
        let session = Session::login_with_proxy(email, password, proxy).await?;
        Ok(SessionActor::spawn(session))
    }

    /// Load a saved session from disk.
    ///
    /// Returns `Ok(None)` when the file does not exist or the stored session can
    /// not be restored.
    ///
    /// # Errors
    /// Returns an error on read failures or invalid file contents.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// if let Some(session) = SessionHandle::load("session.txt").await? {
    ///     session.refresh().await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Option<Self>> {
        let session = Session::load(path).await?;
        Ok(session.map(SessionActor::spawn))
    }

    /// Load a saved session from disk using a proxy.
    ///
    /// Returns `Ok(None)` when the file does not exist or the stored session can
    /// not be restored.
    ///
    /// # Errors
    /// Returns an error on read failures or invalid file contents.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::load_with_proxy("session.txt", "http://proxy:8080").await?;
    /// # let _ = session;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load_with_proxy<P: AsRef<std::path::Path>>(
        path: P,
        proxy: &str,
    ) -> Result<Option<Self>> {
        let session = Session::load_with_proxy(path, proxy).await?;
        Ok(session.map(SessionActor::spawn))
    }

    async fn request<R>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<R>>) -> SessionCommand,
    ) -> Result<R> {
        let (tx, rx) = oneshot::channel();
        let cmd = build(tx);
        self.tx
            .send(cmd)
            .await
            .map_err(|_| MegaError::Custom("Session actor stopped".to_string()))?;
        rx.await
            .map_err(|_| MegaError::Custom("Session actor stopped".to_string()))?
    }

    /// Fetch account metadata for the current session.
    ///
    /// This returns the cached identity information from the session actor.
    ///
    /// # Errors
    /// Returns an error if the session actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// let info = session.account_info().await?;
    /// println!("{}", info.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn account_info(&self) -> Result<AccountInfo> {
        self.request(|reply| SessionCommand::AccountInfo { reply })
            .await
    }

    /// Export the current session as a base64 string.
    ///
    /// The returned value can be saved and later passed to `load`.
    ///
    /// # Errors
    /// Returns an error if the session cannot be serialized or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// let token = session.dump_session().await?;
    /// # let _ = token;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dump_session(&self) -> Result<String> {
        self.request(|reply| SessionCommand::DumpSession { reply })
            .await
    }

    /// Export the current session as a raw blob.
    ///
    /// This is useful for SDK-compatible persistence formats.
    ///
    /// # Errors
    /// Returns an error if the session cannot be serialized or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// let blob = session.dump_session_blob().await?;
    /// # let _ = blob;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dump_session_blob(&self) -> Result<Vec<u8>> {
        self.request(|reply| SessionCommand::DumpSessionBlob { reply })
            .await
    }

    /// Refresh the remote node tree and caches.
    ///
    /// Call this after login and after remote changes to keep path-based operations
    /// accurate.
    ///
    /// # Errors
    /// Returns an error if the refresh request fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh(&self) -> Result<()> {
        self.request(|reply| SessionCommand::Refresh { reply })
            .await
    }

    /// Fetch the current storage quota.
    ///
    /// # Errors
    /// Returns an error if the quota request fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// let quota = session.quota().await?;
    /// println!("{}", quota.used);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn quota(&self) -> Result<Quota> {
        self.request(|reply| SessionCommand::Quota { reply }).await
    }

    /// List files in a directory by path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn list(&self, path: &str, recursive: bool) -> Result<Vec<Node>> {
        self.request(|reply| SessionCommand::List {
            path: path.to_string(),
            recursive,
            reply,
        })
        .await
    }

    /// Get a node by path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn stat(&self, path: &str) -> Result<Option<Node>> {
        self.request(|reply| SessionCommand::Stat {
            path: path.to_string(),
            reply,
        })
        .await
    }

    /// Return the cached node list.
    ///
    /// Call [`SessionHandle::refresh`] to synchronize with the server first.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let nodes = session.nodes().await?;
    /// # let _ = nodes;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn nodes(&self) -> Result<Vec<Node>> {
        self.request(|reply| SessionCommand::Nodes { reply }).await
    }

    /// List cached contact nodes.
    ///
    /// Call [`SessionHandle::refresh`] to synchronize contact data.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let contacts = session.list_contacts().await?;
    /// # let _ = contacts;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_contacts(&self) -> Result<Vec<Node>> {
        self.request(|reply| SessionCommand::ListContacts { reply })
            .await
    }

    /// Look up a cached node by its handle.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// if let Some(node) = session.get_node_by_handle("HANDLE").await? {
    ///     println!("{}", node.name);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_node_by_handle(&self, handle: &str) -> Result<Option<Node>> {
        self.request(|reply| SessionCommand::GetNodeByHandle {
            handle: handle.to_string(),
            reply,
        })
        .await
    }

    /// Check whether a node has the given ancestor.
    ///
    /// This uses the cached node tree; call [`SessionHandle::refresh`] to update it.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let nodes = session.nodes().await?;
    /// if let (Some(node), Some(ancestor)) = (nodes.get(0), nodes.get(1)) {
    ///     let _ = session.node_has_ancestor(node, ancestor).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn node_has_ancestor(&self, node: &Node, ancestor: &Node) -> Result<bool> {
        self.request(|reply| SessionCommand::NodeHasAncestor {
            node_handle: node.handle.clone(),
            ancestor_handle: ancestor.handle.clone(),
            reply,
        })
        .await
    }

    /// Check whether a node has the given ancestor by handle.
    ///
    /// This uses the cached node tree; call [`SessionHandle::refresh`] to update it.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// let ok = session.node_has_ancestor_by_handle("NODE", "ANCESTOR").await?;
    /// # let _ = ok;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn node_has_ancestor_by_handle(
        &self,
        node_handle: &str,
        ancestor_handle: &str,
    ) -> Result<bool> {
        self.request(|reply| SessionCommand::NodeHasAncestor {
            node_handle: node_handle.to_string(),
            ancestor_handle: ancestor_handle.to_string(),
            reply,
        })
        .await
    }

    /// Create a folder at the given path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn mkdir(&self, path: &str) -> Result<Node> {
        self.request(|reply| SessionCommand::Mkdir {
            path: path.to_string(),
            reply,
        })
        .await
    }

    /// Move a node to a new parent path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn mv(&self, source: &str, dest: &str) -> Result<()> {
        self.request(|reply| SessionCommand::Mv {
            source: source.to_string(),
            dest: dest.to_string(),
            reply,
        })
        .await
    }

    /// Rename a node at the given path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn rename(&self, path: &str, new_name: &str) -> Result<()> {
        self.request(|reply| SessionCommand::Rename {
            path: path.to_string(),
            new_name: new_name.to_string(),
            reply,
        })
        .await
    }

    /// Remove a node at the given path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn rm(&self, path: &str) -> Result<()> {
        self.request(|reply| SessionCommand::Rm {
            path: path.to_string(),
            reply,
        })
        .await
    }

    /// Export a node by path to create a public link.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn export(&self, path: &str) -> Result<String> {
        self.request(|reply| SessionCommand::Export {
            path: path.to_string(),
            reply,
        })
        .await
    }

    /// Export multiple nodes by path to create public links.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn export_many(&self, paths: &[&str]) -> Result<Vec<(String, String)>> {
        self.request(|reply| SessionCommand::ExportMany {
            paths: paths.iter().map(|p| p.to_string()).collect(),
            reply,
        })
        .await
    }

    /// Share a folder by handle.
    pub async fn share_folder_handle(&self, handle: &str, email: &str, level: i32) -> Result<()> {
        self.request(|reply| SessionCommand::ShareFolder {
            handle: handle.to_string(),
            email: email.to_string(),
            level,
            reply,
        })
        .await
    }

    /// Share a folder by path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn share_folder(&self, path: &str, email: &str, level: i32) -> Result<()> {
        let node = self
            .stat(path)
            .await?
            .ok_or_else(|| MegaError::Custom(format!("Folder not found: {}", path)))?;
        if !node.is_folder() {
            return Err(MegaError::Custom("Can only share folders".to_string()));
        }
        self.share_folder_handle(&node.handle, email, level).await
    }

    /// Upload a local file into a remote parent path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn upload(&self, local: &str, remote: &str) -> Result<Node> {
        self.request(|reply| SessionCommand::Upload {
            local: local.to_string(),
            remote: remote.to_string(),
            reply,
        })
        .await
    }

    /// Upload raw bytes into a remote parent path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn upload_from_bytes(
        &self,
        data: &[u8],
        filename: &str,
        remote: &str,
    ) -> Result<Node> {
        self.request(|reply| SessionCommand::UploadFromBytes {
            data: data.to_vec(),
            filename: filename.to_string(),
            remote: remote.to_string(),
            reply,
        })
        .await
    }

    /// Upload a reader into a remote parent path.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn upload_from_reader<R>(
        &self,
        reader: R,
        filename: &str,
        size: u64,
        remote: &str,
    ) -> Result<Node>
    where
        R: AsyncRead + AsyncSeek + Unpin + Send + 'static,
    {
        self.request(|reply| SessionCommand::UploadFromReader {
            reader: Box::new(reader),
            filename: filename.to_string(),
            size,
            remote: remote.to_string(),
            reply,
        })
        .await
    }

    /// Upload a local file into a remote parent path with resume support.
    ///
    /// Requires `refresh()` to populate the path cache.
    pub async fn upload_resumable(&self, local: &str, remote_parent: &str) -> Result<Node> {
        self.request(|reply| SessionCommand::UploadResumable {
            local: local.to_string(),
            remote_parent: remote_parent.to_string(),
            reply,
        })
        .await
    }

    /// Download a node to a local file path.
    ///
    /// # Errors
    /// Returns an error if the download fails or the destination cannot be written.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// if let Some(node) = session.stat("/Root/file.txt").await? {
    ///     session.download_to_file(&node, "file.txt").await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_to_file<P: AsRef<std::path::Path>>(
        &self,
        node: &Node,
        path: P,
    ) -> Result<()> {
        self.request(|reply| SessionCommand::DownloadToFile {
            node: node.clone(),
            path: path.as_ref().to_path_buf(),
            reply,
        })
        .await
    }

    /// Download a node into a writer.
    ///
    /// # Errors
    /// Returns an error if the download fails or writing to the sink fails.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// if let Some(node) = session.stat("/Root/file.txt").await? {
    ///     let writer = Box::new(std::io::Cursor::new(Vec::new()));
    ///     session.download_to_writer(&node, writer).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_to_writer(&self, node: &Node, writer: BoxedWriter) -> Result<()> {
        self.download_to_writer_with_offset(node, writer, 0).await
    }

    /// Download a node into a writer starting at a byte offset.
    ///
    /// This is useful for resumable downloads.
    ///
    /// # Errors
    /// Returns an error if the download fails or writing to the sink fails.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.refresh().await?;
    /// if let Some(node) = session.stat("/Root/file.txt").await? {
    ///     let writer = Box::new(std::io::Cursor::new(Vec::new()));
    ///     session.download_to_writer_with_offset(&node, writer, 0).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn download_to_writer_with_offset(
        &self,
        node: &Node,
        writer: BoxedWriter,
        offset: u64,
    ) -> Result<()> {
        self.request(|reply| SessionCommand::DownloadToWriter {
            node: node.clone(),
            writer,
            offset,
            reply,
        })
        .await
    }

    /// Set the number of concurrent transfer workers.
    ///
    /// Higher values can improve throughput for large transfers.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_workers(4).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_workers(&self, workers: usize) -> Result<()> {
        self.request(|reply| SessionCommand::SetWorkers { workers, reply })
            .await
    }

    /// Enable or disable resumable transfers.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_resume(true).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_resume(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::SetResume { enabled, reply })
            .await
    }

    /// Clear any registered transfer progress callback.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.clear_status().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn clear_status(&self) -> Result<()> {
        self.request(|reply| SessionCommand::ClearStatus { reply })
            .await
    }

    /// Enable or disable preview thumbnail generation for uploads.
    ///
    /// Note: Preview generation requires the crate `preview` feature.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.enable_previews(true).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn enable_previews(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::EnablePreviews { enabled, reply })
            .await
    }

    /// Replace the Ed25519 authring blob and persist it.
    ///
    /// # Errors
    /// Returns an error if persistence fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_authring_ed25519(Vec::new()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_authring_ed25519(&self, blob: Vec<u8>) -> Result<()> {
        self.request(|reply| SessionCommand::SetAuthringEd25519 { blob, reply })
            .await
    }

    /// Replace the Cu25519 authring blob and persist it.
    ///
    /// # Errors
    /// Returns an error if persistence fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_authring_cu25519(Vec::new()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_authring_cu25519(&self, blob: Vec<u8>) -> Result<()> {
        self.request(|reply| SessionCommand::SetAuthringCu25519 { blob, reply })
            .await
    }

    /// Replace the backups blob and persist it.
    ///
    /// # Errors
    /// Returns an error if persistence fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_backups_blob(Vec::new()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_backups_blob(&self, blob: Vec<u8>) -> Result<()> {
        self.request(|reply| SessionCommand::SetBackupsBlob { blob, reply })
            .await
    }

    /// Replace the warnings map and persist it.
    ///
    /// # Errors
    /// Returns an error if persistence fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    /// use megalib::crypto::Warnings;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_warnings(Warnings::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_warnings(&self, warnings: Warnings) -> Result<()> {
        self.request(|reply| SessionCommand::SetWarnings { warnings, reply })
            .await
    }

    /// Enable or disable the contact verification warning flag.
    ///
    /// # Errors
    /// Returns an error if persistence fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_contact_verification_warning(true).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_contact_verification_warning(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::SetContactVerificationWarning { enabled, reply })
            .await
    }

    /// Enable or disable manual verification gating for share keys.
    ///
    /// # Errors
    /// Returns an error if persistence fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.set_manual_verification(true).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set_manual_verification(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::SetManualVerification { enabled, reply })
            .await
    }

    /// Check whether a ^!keys downgrade was detected.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// let flagged = session.keys_downgrade_detected().await?;
    /// # let _ = flagged;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn keys_downgrade_detected(&self) -> Result<bool> {
        self.request(|reply| SessionCommand::KeysDowngradeDetected { reply })
            .await
    }

    /// Check whether the contact verification warning flag is set.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// let enabled = session.contact_verification_warning().await?;
    /// # let _ = enabled;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn contact_verification_warning(&self) -> Result<bool> {
        self.request(|reply| SessionCommand::ContactVerificationWarning { reply })
            .await
    }

    /// Look up authring state for a contact handle.
    ///
    /// Returns a tuple of `(ed25519_state, cu25519_state)`.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// let states = session.authring_state("BASE64_HANDLE").await?;
    /// # let _ = states;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn authring_state(
        &self,
        handle_b64: &str,
    ) -> Result<(Option<AuthState>, Option<AuthState>)> {
        self.request(|reply| SessionCommand::AuthringState {
            handle: handle_b64.to_string(),
            reply,
        })
        .await
    }

    /// Register a transfer progress callback.
    ///
    /// The callback receives [`crate::progress::TransferProgress`] updates and
    /// should return `true` to continue or `false` to cancel.
    ///
    /// # Errors
    /// Returns an error if the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.watch_status(Box::new(|progress| {
    ///     println!("{}% complete", progress.percent() as u32);
    ///     true
    /// })).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn watch_status(&self, callback: ProgressCallback) -> Result<()> {
        self.request(|reply| SessionCommand::WatchStatus { callback, reply })
            .await
    }

    /// Change the account password.
    ///
    /// This re-encrypts the master key with a new password-derived key.
    ///
    /// # Errors
    /// Returns an error if the update request fails or the actor has stopped.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "old_password").await?;
    /// session.change_password("new_password").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn change_password(&self, new_password: &str) -> Result<()> {
        self.request(|reply| SessionCommand::ChangePassword {
            new_password: new_password.to_string(),
            reply,
        })
        .await
    }

    /// Save the current session to disk.
    ///
    /// The saved file can be restored with [`SessionHandle::load`].
    ///
    /// # Errors
    /// Returns an error if the session cannot be serialized or written.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.save("session.txt").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn save<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        self.request(|reply| SessionCommand::Save {
            path: path.as_ref().to_path_buf(),
            reply,
        })
        .await
    }

    /// Shut down the background session actor.
    ///
    /// Pending requests will be dropped after shutdown completes.
    ///
    /// # Examples
    /// ```no_run
    /// use megalib::SessionHandle;
    ///
    /// # async fn example() -> megalib::Result<()> {
    /// let session = SessionHandle::login("user@example.com", "password").await?;
    /// session.shutdown().await;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(SessionCommand::Shutdown { reply: tx }).await;
        let _ = rx.await;
    }
}

impl SessionActor {
    fn spawn(session: Session) -> SessionHandle {
        let last_key_generation = session.key_manager.generation;
        let (tx, rx) = mpsc::channel(64);
        let (sc_event_tx, sc_event_rx) = mpsc::channel(64);
        let (sc_control_tx, sc_control_rx) = mpsc::channel(16);
        let poller_state = ScPollerState {
            scsn: session.scsn.clone(),
            wsc_url: session.wsc_url.clone(),
            sc_catchup: session.sc_catchup,
            alerts_catchup_pending: session.alerts_catchup_pending,
        };
        let poller = ScPoller::new(
            session.api.clone(),
            poller_state,
            sc_event_tx,
            sc_control_rx,
        );
        let sc_poller_task = tokio::spawn(poller.run());
        let actor = SessionActor {
            session,
            rx,
            sc_event_rx,
            sc_control_tx,
            sc_poller_task: Some(sc_poller_task),
            seqtag_waiters: HashMap::new(),
            key_work_queue: VecDeque::new(),
            deferred_key_work_enqueued: 0,
            deferred_key_work_coalesced: 0,
            deferred_key_work_started: 0,
            deferred_key_work_retried: 0,
            deferred_key_work_dropped: 0,
            deferred_key_work_queue_hwm: 0,
            ap_pk_seen: 0,
            pending_keys_fetch_queued: 0,
            pending_keys_fetch_started: 0,
            state_current_transitions: 0,
            action_packets_current_transitions: 0,
            deferred_pk_bursts: 0,
            startup_reconciliation_requested: false,
            startup_reconciliation_queued: false,
            startup_reconciliation_enqueued: 0,
            startup_reconciliation_started: 0,
            startup_reconciliation_completed: 0,
            startup_reconciliation_retried: 0,
            startup_reconciliation_dropped: 0,
            last_key_generation,
            persist_requested: 0,
            persist_started: 0,
            persist_coalesced: 0,
        };
        tokio::spawn(actor.run());
        SessionHandle { tx }
    }

    fn push_seqtag_waiter(&mut self, seqtag: String, waiter: SeqtagWaiter) {
        self.seqtag_waiters.entry(seqtag).or_default().push(waiter);
    }

    fn resolve_seqtag_waiters(&mut self, seqtags: &[String]) {
        for seqtag in seqtags {
            if let Some(waiters) = self.seqtag_waiters.remove(seqtag) {
                for waiter in waiters {
                    waiter(&mut self.session);
                }
            }
        }
    }

    fn sc_poller_state(&self) -> ScPollerState {
        ScPollerState {
            scsn: self.session.scsn.clone(),
            wsc_url: self.session.wsc_url.clone(),
            sc_catchup: self.session.sc_catchup,
            alerts_catchup_pending: self.session.alerts_catchup_pending,
        }
    }

    async fn sync_sc_state_to_poller(&mut self) {
        let _ = self
            .sc_control_tx
            .send(ScPollerControl::UpdateState(self.sc_poller_state()))
            .await;
    }

    fn deferred_retry_backoff(attempt: u8) -> Duration {
        match attempt {
            1 => Duration::from_millis(100),
            2 => Duration::from_millis(500),
            3 => Duration::from_secs(2),
            _ => Duration::from_secs(5),
        }
    }

    fn update_deferred_queue_hwm(&mut self) {
        let len = self.key_work_queue.len();
        if len > self.deferred_key_work_queue_hwm {
            self.deferred_key_work_queue_hwm = len;
        }
    }

    fn seqtag_high_watermark_pending(&self) -> bool {
        !self.seqtag_waiters.is_empty()
            || (self.session.current_seqtag.is_some() && !self.session.current_seqtag_seen)
    }

    fn should_run_startup_reconciliation(&self) -> bool {
        self.session.is_full_account_session() && self.session.key_manager.generation > 0
    }

    fn maybe_enqueue_startup_reconciliation(&mut self) {
        if !self.startup_reconciliation_requested
            || self.startup_reconciliation_queued
            || !self.session.state_current
            || !self.should_run_startup_reconciliation()
        {
            return;
        }
        self.startup_reconciliation_queued = true;
        self.startup_reconciliation_enqueued = self.startup_reconciliation_enqueued.saturating_add(1);
        self.key_work_queue
            .push_back(DeferredKeyWork::StartupReconciliation {
                attempts: 0,
                ready_at: Instant::now(),
            });
        self.update_deferred_queue_hwm();
        debug!(
            startup_reconciliation_enqueued = self.startup_reconciliation_enqueued,
            startup_reconciliation_started = self.startup_reconciliation_started,
            startup_reconciliation_completed = self.startup_reconciliation_completed,
            deferred_pk_bursts = self.deferred_pk_bursts,
            deferred_key_work_queue_len = self.key_work_queue.len(),
            deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
            "queued startup key reconciliation pass"
        );
    }

    fn request_startup_reconciliation(&mut self, reason: &str) {
        self.startup_reconciliation_requested = true;
        debug!(
            reason,
            state_current = self.session.state_current,
            nodes_state_ready = self.session.nodes_state_ready,
            sc_batch_catchup_done = self.session.sc_batch_catchup_done,
            key_generation = self.session.key_manager.generation,
            full_account_session = self.session.is_full_account_session(),
            deferred_pk_bursts = self.deferred_pk_bursts,
            "startup key reconciliation requested"
        );
        self.maybe_enqueue_startup_reconciliation();
    }

    fn refresh_state_current_flags(&mut self) {
        let previous_state_current = self.session.state_current;
        self.session.recompute_state_current();
        if previous_state_current != self.session.state_current {
            if self.session.state_current {
                self.state_current_transitions = self.state_current_transitions.saturating_add(1);
                debug!(
                    state_current_transitions = self.state_current_transitions,
                    nodes_state_ready = self.session.nodes_state_ready,
                    sc_batch_catchup_done = self.session.sc_batch_catchup_done,
                    deferred_pk_bursts = self.deferred_pk_bursts,
                    "state_current=false -> true"
                );
                if self.should_run_startup_reconciliation() {
                    self.request_startup_reconciliation("state_current_transition");
                } else {
                    debug!(
                        key_generation = self.session.key_manager.generation,
                        full_account_session = self.session.is_full_account_session(),
                        "state_current reached but startup reconciliation is gated"
                    );
                }
            } else {
                debug!(
                    nodes_state_ready = self.session.nodes_state_ready,
                    sc_batch_catchup_done = self.session.sc_batch_catchup_done,
                    "state_current=true -> false"
                );
            }
        }

        let seqtag_high_watermark_pending = self.seqtag_high_watermark_pending();
        let previous_ap_current = self.session.action_packets_current;
        self.session.action_packets_current =
            self.session.state_current && !seqtag_high_watermark_pending;
        if previous_ap_current != self.session.action_packets_current {
            self.action_packets_current_transitions =
                self.action_packets_current_transitions.saturating_add(1);
            debug!(
                action_packets_current_transitions = self.action_packets_current_transitions,
                action_packets_current = self.session.action_packets_current,
                state_current = self.session.state_current,
                seqtag_high_watermark_pending,
                pending_seqtag_waiters = self.seqtag_waiters.len(),
                "action_packets_current transition"
            );
        }
    }

    fn check_generation_upgrade_transition(&mut self) {
        let current_generation = self.session.key_manager.generation;
        if self.last_key_generation == 0
            && current_generation > 0
            && self.session.is_full_account_session()
        {
            debug!(
                generation_previous = self.last_key_generation,
                generation_current = current_generation,
                state_current = self.session.state_current,
                "detected key generation upgrade; scheduling reconciliation"
            );
            self.request_startup_reconciliation("post_upgrade_generation_transition");
        }
        self.last_key_generation = current_generation;
    }

    fn refresh_runtime_state(&mut self) {
        self.refresh_state_current_flags();
        self.check_generation_upgrade_transition();
        self.maybe_enqueue_startup_reconciliation();
    }

    fn schedule_keys_persist(&mut self, reason: &str) {
        if self.session.keys_persist_dirty {
            self.persist_coalesced = self.persist_coalesced.saturating_add(1);
            debug!(
                reason,
                persist_requested = self.persist_requested,
                persist_started = self.persist_started,
                persist_coalesced = self.persist_coalesced,
                "coalesced keys persist request"
            );
            return;
        }
        self.session.keys_persist_dirty = true;
        self.persist_requested = self.persist_requested.saturating_add(1);
        debug!(
            reason,
            persist_requested = self.persist_requested,
            persist_started = self.persist_started,
            persist_coalesced = self.persist_coalesced,
            "scheduled keys persist flush"
        );
    }

    async fn flush_keys_persist_if_dirty(&mut self, force: bool) {
        if !self.session.keys_persist_dirty {
            return;
        }
        if self.session.keys_persist_inflight {
            debug!(
                force_flush = force,
                persist_requested = self.persist_requested,
                persist_started = self.persist_started,
                persist_coalesced = self.persist_coalesced,
                "keys persist already inflight; deferring flush"
            );
            return;
        }

        self.persist_started = self.persist_started.saturating_add(1);
        self.session.keys_persist_dirty = false;
        let started = Instant::now();
        match self.session.persist_keys_with_retry().await {
            Ok(()) => {
                debug!(
                    persist_requested = self.persist_requested,
                    persist_started = self.persist_started,
                    persist_coalesced = self.persist_coalesced,
                    persist_flush_ms = started.elapsed().as_millis() as u64,
                    "keys persist flush completed"
                );
            }
            Err(err) => {
                self.session.keys_persist_dirty = true;
                debug!(
                    error = %err,
                    persist_requested = self.persist_requested,
                    persist_started = self.persist_started,
                    persist_coalesced = self.persist_coalesced,
                    persist_flush_ms = started.elapsed().as_millis() as u64,
                    "keys persist flush failed; will retry"
                );
            }
        }
    }

    fn enqueue_key_work(&mut self, work: ActionPacketKeyWork) {
        if work.is_empty() {
            return;
        }
        let now = Instant::now();
        self.deferred_key_work_enqueued = self.deferred_key_work_enqueued.saturating_add(1);
        if let Some(DeferredKeyWork::FromActionPacket {
            work: queued_work,
            attempts,
            ready_at,
        }) = self.key_work_queue.back_mut()
        {
            if *attempts == 0 {
                queued_work.merge_from(work);
                *ready_at = now;
                self.deferred_key_work_coalesced =
                    self.deferred_key_work_coalesced.saturating_add(1);
                debug!(
                    deferred_key_work_enqueued = self.deferred_key_work_enqueued,
                    deferred_key_work_coalesced = self.deferred_key_work_coalesced,
                    deferred_key_work_queue_len = self.key_work_queue.len(),
                    deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
                    "coalesced deferred key work from action packets"
                );
                return;
            }
        }
        let mut queued_work = work;
        if self.key_work_queue.len() >= MAX_DEFERRED_KEY_WORK_QUEUE {
            if let Some(DeferredKeyWork::FromActionPacket {
                work: oldest_work, ..
            }) = self.key_work_queue.pop_front()
            {
                queued_work.merge_from(oldest_work);
                self.deferred_key_work_coalesced =
                    self.deferred_key_work_coalesced.saturating_add(1);
                debug!(
                    deferred_key_work_enqueued = self.deferred_key_work_enqueued,
                    deferred_key_work_coalesced = self.deferred_key_work_coalesced,
                    deferred_key_work_queue_len = self.key_work_queue.len(),
                    deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
                    queue_limit = MAX_DEFERRED_KEY_WORK_QUEUE,
                    "deferred key work queue at capacity; merged oldest item into new work"
                );
            }
        }
        self.key_work_queue
            .push_back(DeferredKeyWork::FromActionPacket {
                work: queued_work,
                attempts: 0,
                ready_at: now,
            });
        self.update_deferred_queue_hwm();
        debug!(
            deferred_key_work_enqueued = self.deferred_key_work_enqueued,
            deferred_key_work_coalesced = self.deferred_key_work_coalesced,
            deferred_key_work_queue_len = self.key_work_queue.len(),
            deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
            "queued deferred key work from action packets"
        );
    }

    fn enqueue_pending_keys_fetch(&mut self) {
        self.pending_keys_fetch_queued = self.pending_keys_fetch_queued.saturating_add(1);
        self.key_work_queue
            .push_back(DeferredKeyWork::PendingKeysFetch {
                attempts: 0,
                ready_at: Instant::now(),
            });
        self.update_deferred_queue_hwm();
        debug!(
            ap_pk_seen = self.ap_pk_seen,
            pending_keys_fetch_queued = self.pending_keys_fetch_queued,
            deferred_key_work_queue_len = self.key_work_queue.len(),
            deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
            "queued sdk-style pending keys fetch from action packet"
        );
    }

    async fn process_deferred_key_work_once(&mut self) {
        let now = Instant::now();
        let Some(idx) = self.key_work_queue.iter().position(|work| work.is_due(now)) else {
            return;
        };
        if let Some(work) = self.key_work_queue.remove(idx) {
            match work {
                DeferredKeyWork::FromActionPacket { work, attempts, .. } => {
                    self.deferred_key_work_started =
                        self.deferred_key_work_started.saturating_add(1);
                    let retry_work = work.clone();
                    match self.session.execute_actionpacket_key_work(work).await {
                        Ok(changed) => {
                            if changed {
                                self.schedule_keys_persist("action_packet_key_work");
                            }
                        }
                        Err(err) => {
                            let next_attempt = attempts.saturating_add(1);
                            if next_attempt <= MAX_DEFERRED_KEY_WORK_RETRIES {
                                let retry_backoff = Self::deferred_retry_backoff(next_attempt);
                                self.deferred_key_work_retried =
                                    self.deferred_key_work_retried.saturating_add(1);
                                self.key_work_queue
                                    .push_back(DeferredKeyWork::FromActionPacket {
                                        work: retry_work,
                                        attempts: next_attempt,
                                        ready_at: Instant::now() + retry_backoff,
                                    });
                                self.update_deferred_queue_hwm();
                                debug!(
                                    error = %err,
                                    attempt = next_attempt,
                                    max_attempts = MAX_DEFERRED_KEY_WORK_RETRIES,
                                    retry_backoff_ms = retry_backoff.as_millis() as u64,
                                    deferred_key_work_started = self.deferred_key_work_started,
                                    deferred_key_work_retried = self.deferred_key_work_retried,
                                    deferred_key_work_queue_len = self.key_work_queue.len(),
                                    deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
                                    "deferred key work failed; requeued for retry"
                                );
                            } else {
                                self.deferred_key_work_dropped =
                                    self.deferred_key_work_dropped.saturating_add(1);
                                debug!(
                                    error = %err,
                                    attempts = next_attempt,
                                    max_attempts = MAX_DEFERRED_KEY_WORK_RETRIES,
                                    deferred_key_work_started = self.deferred_key_work_started,
                                    deferred_key_work_retried = self.deferred_key_work_retried,
                                    deferred_key_work_dropped = self.deferred_key_work_dropped,
                                    "deferred key work failed; dropping after max retries"
                                );
                            }
                        }
                    }
                }
                DeferredKeyWork::PendingKeysFetch { attempts, .. } => {
                    self.pending_keys_fetch_started =
                        self.pending_keys_fetch_started.saturating_add(1);
                    match self.session.handle_actionpacket_pending_keys_fetch().await {
                        Ok(changed) => {
                            if changed {
                                self.schedule_keys_persist("pending_keys_fetch");
                            }
                        }
                        Err(err) => {
                            let next_attempt = attempts.saturating_add(1);
                            if next_attempt <= MAX_DEFERRED_KEY_WORK_RETRIES {
                                let retry_backoff = Self::deferred_retry_backoff(next_attempt);
                                self.deferred_key_work_retried =
                                    self.deferred_key_work_retried.saturating_add(1);
                                self.key_work_queue
                                    .push_back(DeferredKeyWork::PendingKeysFetch {
                                        attempts: next_attempt,
                                        ready_at: Instant::now() + retry_backoff,
                                    });
                                self.update_deferred_queue_hwm();
                                debug!(
                                    error = %err,
                                    attempt = next_attempt,
                                    max_attempts = MAX_DEFERRED_KEY_WORK_RETRIES,
                                    retry_backoff_ms = retry_backoff.as_millis() as u64,
                                    pending_keys_fetch_started = self.pending_keys_fetch_started,
                                    deferred_key_work_retried = self.deferred_key_work_retried,
                                    deferred_key_work_queue_len = self.key_work_queue.len(),
                                    deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
                                    "pending keys fetch failed; requeued for retry"
                                );
                            } else {
                                self.deferred_key_work_dropped =
                                    self.deferred_key_work_dropped.saturating_add(1);
                                debug!(
                                    error = %err,
                                    attempts = next_attempt,
                                    max_attempts = MAX_DEFERRED_KEY_WORK_RETRIES,
                                    pending_keys_fetch_started = self.pending_keys_fetch_started,
                                    deferred_key_work_retried = self.deferred_key_work_retried,
                                    deferred_key_work_dropped = self.deferred_key_work_dropped,
                                    "pending keys fetch failed; dropping after max retries"
                                );
                            }
                        }
                    }
                }
                DeferredKeyWork::StartupReconciliation { attempts, .. } => {
                    self.startup_reconciliation_started =
                        self.startup_reconciliation_started.saturating_add(1);
                    match self.session.run_startup_key_reconciliation().await {
                        Ok(changed) => {
                            if changed {
                                self.schedule_keys_persist("startup_reconciliation");
                            }
                            self.startup_reconciliation_completed =
                                self.startup_reconciliation_completed.saturating_add(1);
                            self.startup_reconciliation_requested = false;
                            self.startup_reconciliation_queued = false;
                            self.deferred_pk_bursts = 0;
                            debug!(
                                startup_reconciliation_enqueued = self.startup_reconciliation_enqueued,
                                startup_reconciliation_started = self.startup_reconciliation_started,
                                startup_reconciliation_completed = self.startup_reconciliation_completed,
                                startup_reconciliation_retried = self.startup_reconciliation_retried,
                                startup_reconciliation_dropped = self.startup_reconciliation_dropped,
                                "startup key reconciliation completed"
                            );
                        }
                        Err(err) => {
                            let next_attempt = attempts.saturating_add(1);
                            if next_attempt <= MAX_DEFERRED_KEY_WORK_RETRIES {
                                let retry_backoff = Self::deferred_retry_backoff(next_attempt);
                                self.startup_reconciliation_retried =
                                    self.startup_reconciliation_retried.saturating_add(1);
                                self.key_work_queue
                                    .push_back(DeferredKeyWork::StartupReconciliation {
                                        attempts: next_attempt,
                                        ready_at: Instant::now() + retry_backoff,
                                    });
                                self.update_deferred_queue_hwm();
                                debug!(
                                    error = %err,
                                    attempt = next_attempt,
                                    max_attempts = MAX_DEFERRED_KEY_WORK_RETRIES,
                                    retry_backoff_ms = retry_backoff.as_millis() as u64,
                                    startup_reconciliation_started = self.startup_reconciliation_started,
                                    startup_reconciliation_retried = self.startup_reconciliation_retried,
                                    deferred_key_work_queue_len = self.key_work_queue.len(),
                                    deferred_key_work_queue_hwm = self.deferred_key_work_queue_hwm,
                                    "startup key reconciliation failed; requeued for retry"
                                );
                            } else {
                                self.startup_reconciliation_dropped =
                                    self.startup_reconciliation_dropped.saturating_add(1);
                                self.startup_reconciliation_requested = false;
                                self.startup_reconciliation_queued = false;
                                self.deferred_pk_bursts = 0;
                                debug!(
                                    error = %err,
                                    attempts = next_attempt,
                                    max_attempts = MAX_DEFERRED_KEY_WORK_RETRIES,
                                    startup_reconciliation_started = self.startup_reconciliation_started,
                                    startup_reconciliation_retried = self.startup_reconciliation_retried,
                                    startup_reconciliation_dropped = self.startup_reconciliation_dropped,
                                    "startup key reconciliation failed; dropping after max retries"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    async fn drain_pending_commands(&mut self) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(cmd) => {
                    if self.handle_command(cmd).await {
                        return true;
                    }
                }
                Err(TryRecvError::Empty) => return false,
                Err(TryRecvError::Disconnected) => return true,
            }
        }
    }

    async fn handle_sc_event(&mut self, event: ScPollerEvent) {
        match event {
            ScPollerEvent::ScBatch {
                packets,
                seqtags,
                next_sn,
                next_wsc_url,
                ir,
                poll_catchup,
            } => {
                self.session.scsn = Some(next_sn);
                if let Some(w) = next_wsc_url {
                    self.session.wsc_url = Some(w);
                }
                self.session.sc_catchup = poll_catchup && ir;
                if poll_catchup {
                    self.session.sc_batch_catchup_done = !ir;
                } else {
                    self.session.sc_batch_catchup_done = true;
                }
                self.refresh_runtime_state();
                let started = Instant::now();
                match self.session.dispatch_action_packets(&packets).await {
                    Ok(dispatch) => {
                        if dispatch.ap_pk_seen {
                            self.ap_pk_seen = self.ap_pk_seen.saturating_add(1);
                            if !self.session.state_current {
                                self.deferred_pk_bursts =
                                    self.deferred_pk_bursts.saturating_add(1);
                                debug!(
                                    deferred_pk_bursts = self.deferred_pk_bursts,
                                    state_current = self.session.state_current,
                                    "deferred AP-triggered pending-key work until state_current"
                                );
                                self.request_startup_reconciliation("deferred_ap_pk");
                            }
                        }
                        debug!(
                            ap_packets = packets.len(),
                            ap_pk_seen = dispatch.ap_pk_seen,
                            ap_pk_seen_total = self.ap_pk_seen,
                            pending_keys_fetch_queued = dispatch.pending_keys_fetch,
                            ap_parse_apply_ms = started.elapsed().as_millis() as u64,
                            deferred_key_work_enqueued = dispatch.deferred_key_work.is_some(),
                            "processed action packet batch"
                        );
                        if let Some(work) = dispatch.deferred_key_work {
                            self.enqueue_key_work(work);
                        }
                        if dispatch.pending_keys_fetch {
                            self.enqueue_pending_keys_fetch();
                        }
                    }
                    Err(err) => {
                        debug!(
                            error = %err,
                            ap_packets = packets.len(),
                            ap_parse_apply_ms = started.elapsed().as_millis() as u64,
                            "action packet batch processing failed"
                        );
                    }
                }
                if !seqtags.is_empty() {
                    self.resolve_seqtag_waiters(&seqtags);
                }
                self.refresh_runtime_state();
            }
            ScPollerEvent::AlertsBatch { alerts, lsn } => {
                if !alerts.is_empty() {
                    self.session.user_alerts.extend(alerts);
                }
                if let Some(token) = lsn {
                    self.session.user_alert_lsn = Some(token);
                }
                self.session.alerts_catchup_pending = false;
            }
        }
    }

    async fn stop_sc_poller(&mut self) {
        let _ = self.sc_control_tx.send(ScPollerControl::Shutdown).await;
        if let Some(task) = self.sc_poller_task.take() {
            let _ = task.await;
        }
    }

    async fn run(mut self) {
        self.refresh_runtime_state();
        loop {
            tokio::select! {
                cmd = self.rx.recv() => {
                    let Some(cmd) = cmd else { break; };
                    if self.handle_command(cmd).await {
                        break;
                    }
                }
                sc_event = self.sc_event_rx.recv() => {
                    let Some(event) = sc_event else { break; };
                    self.handle_sc_event(event).await;
                }
                _ = tokio::time::sleep(DEFERRED_KEY_WORK_POLL_INTERVAL), if !self.key_work_queue.is_empty() => {}
            }
            if self.drain_pending_commands().await {
                self.flush_keys_persist_if_dirty(true).await;
                break;
            }
            self.process_deferred_key_work_once().await;
            let has_more_due_key_work = self
                .key_work_queue
                .iter()
                .any(|work| work.is_due(Instant::now()));
            if !has_more_due_key_work {
                self.flush_keys_persist_if_dirty(false).await;
            }
            self.refresh_runtime_state();
        }
        self.flush_keys_persist_if_dirty(true).await;
        self.stop_sc_poller().await;
    }

    async fn handle_command(&mut self, cmd: SessionCommand) -> bool {
        match cmd {
            SessionCommand::AccountInfo { reply } => {
                let info = AccountInfo {
                    email: self.session.email.clone(),
                    name: self.session.name.clone(),
                    user_handle: self.session.user_handle.clone(),
                    session_id: self.session.session_id().to_string(),
                };
                let _ = reply.send(Ok(info));
            }
            SessionCommand::DumpSession { reply } => {
                let res = self.session.dump_session();
                let _ = reply.send(res);
            }
            SessionCommand::DumpSessionBlob { reply } => {
                let res = self.session.dump_session_blob();
                let _ = reply.send(res);
            }
            SessionCommand::Refresh { reply } => {
                let res = self.session.refresh().await;
                if res.is_ok() {
                    self.sync_sc_state_to_poller().await;
                }
                let _ = reply.send(res);
            }
            SessionCommand::Quota { reply } => {
                let res = self.session.quota().await;
                let _ = reply.send(res);
            }
            SessionCommand::List {
                path,
                recursive,
                reply,
            } => {
                let res = self
                    .session
                    .list(&path, recursive)
                    .map(|nodes| nodes.into_iter().cloned().collect());
                let _ = reply.send(res);
            }
            SessionCommand::Stat { path, reply } => {
                let res = Ok(self.session.stat(&path).cloned());
                let _ = reply.send(res);
            }
            SessionCommand::Nodes { reply } => {
                let res: Result<Vec<Node>> = Ok(self.session.nodes().iter().cloned().collect());
                let _ = reply.send(res);
            }
            SessionCommand::ListContacts { reply } => {
                let res: Result<Vec<Node>> =
                    Ok(self.session.list_contacts().into_iter().cloned().collect());
                let _ = reply.send(res);
            }
            SessionCommand::GetNodeByHandle { handle, reply } => {
                let res: Result<Option<Node>> =
                    Ok(self.session.get_node_by_handle(&handle).cloned());
                let _ = reply.send(res);
            }
            SessionCommand::NodeHasAncestor {
                node_handle,
                ancestor_handle,
                reply,
            } => {
                let res = match (
                    self.session.get_node_by_handle(&node_handle),
                    self.session.get_node_by_handle(&ancestor_handle),
                ) {
                    (Some(node), Some(ancestor)) => {
                        Ok(self.session.node_has_ancestor(node, ancestor))
                    }
                    _ => Ok(false),
                };
                let _ = reply.send(res);
            }
            SessionCommand::Mkdir { path, reply } => {
                let res = self.session.mkdir(&path).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    let path_clone = path.clone();
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |session| {
                            let final_res = match res {
                                Ok(node) => Ok(node),
                                Err(err) => session.stat(&path_clone).cloned().ok_or(err),
                            };
                            let _ = reply.send(final_res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::Mv {
                source,
                dest,
                reply,
            } => {
                let res = self.session.mv(&source, &dest).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |_session| {
                            let _ = reply.send(res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::Rename {
                path,
                new_name,
                reply,
            } => {
                let res = self.session.rename(&path, &new_name).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |_session| {
                            let _ = reply.send(res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::Rm { path, reply } => {
                let res = self.session.rm(&path).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |_session| {
                            let _ = reply.send(res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::Export { path, reply } => {
                let res = self.session.export(&path).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |_session| {
                            let _ = reply.send(res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::ExportMany { paths, reply } => {
                let path_refs: Vec<&str> = paths.iter().map(|p| p.as_str()).collect();
                let res = self.session.export_many(&path_refs).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |_session| {
                            let _ = reply.send(res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::ShareFolder {
                handle,
                email,
                level,
                reply,
            } => {
                let res = self.session.share_folder(&handle, &email, level).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |_session| {
                            let _ = reply.send(res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::Upload {
                local,
                remote,
                reply,
            } => {
                let res = self.session.upload(&local, &remote).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    let target_path = build_target_path(&remote, &local);
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |session| {
                            let final_res = match res {
                                Ok(node) => Ok(node),
                                Err(err) => session.stat(&target_path).cloned().ok_or(err),
                            };
                            let _ = reply.send(final_res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::UploadFromBytes {
                data,
                filename,
                remote,
                reply,
            } => {
                let res = self
                    .session
                    .upload_from_bytes(&data, &filename, &remote)
                    .await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    let target_path = join_remote_path(&remote, &filename);
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |session| {
                            let final_res = match res {
                                Ok(node) => Ok(node),
                                Err(err) => session.stat(&target_path).cloned().ok_or(err),
                            };
                            let _ = reply.send(final_res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::UploadFromReader {
                reader,
                filename,
                size,
                remote,
                reply,
            } => {
                let res = self
                    .session
                    .upload_from_reader(reader, &filename, size, &remote)
                    .await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    let target_path = join_remote_path(&remote, &filename);
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |session| {
                            let final_res = match res {
                                Ok(node) => Ok(node),
                                Err(err) => session.stat(&target_path).cloned().ok_or(err),
                            };
                            let _ = reply.send(final_res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::UploadResumable {
                local,
                remote_parent,
                reply,
            } => {
                let res = self.session.upload_resumable(&local, &remote_parent).await;
                let seqtag = self.session.current_seqtag.take();
                self.session.current_seqtag_seen = false;
                if let Some(tag) = seqtag {
                    let target_path = build_target_path(&remote_parent, &local);
                    self.push_seqtag_waiter(
                        tag,
                        Box::new(move |session| {
                            let final_res = match res {
                                Ok(node) => Ok(node),
                                Err(err) => session.stat(&target_path).cloned().ok_or(err),
                            };
                            let _ = reply.send(final_res);
                        }),
                    );
                } else {
                    let _ = reply.send(res);
                }
            }
            SessionCommand::DownloadToFile { node, path, reply } => {
                let res = self.session.download_to_file(&node, path).await;
                let _ = reply.send(res);
            }
            SessionCommand::DownloadToWriter {
                node,
                mut writer,
                offset,
                reply,
            } => {
                let res = if offset == 0 {
                    self.session.download(&node, writer.as_mut()).await
                } else {
                    self.session
                        .download_with_offset(&node, writer.as_mut(), offset)
                        .await
                };
                let _ = reply.send(res);
            }
            SessionCommand::SetWorkers { workers, reply } => {
                self.session.set_workers(workers);
                let _ = reply.send(Ok(()));
            }
            SessionCommand::SetResume { enabled, reply } => {
                self.session.set_resume(enabled);
                let _ = reply.send(Ok(()));
            }
            SessionCommand::ClearStatus { reply } => {
                self.session.clear_status();
                let _ = reply.send(Ok(()));
            }
            SessionCommand::EnablePreviews { enabled, reply } => {
                self.session.enable_previews(enabled);
                let _ = reply.send(Ok(()));
            }
            SessionCommand::SetAuthringEd25519 { blob, reply } => {
                let res = self.session.set_authring_ed25519(blob).await;
                let _ = reply.send(res);
            }
            SessionCommand::SetAuthringCu25519 { blob, reply } => {
                let res = self.session.set_authring_cu25519(blob).await;
                let _ = reply.send(res);
            }
            SessionCommand::SetBackupsBlob { blob, reply } => {
                let res = self.session.set_backups_blob(blob).await;
                let _ = reply.send(res);
            }
            SessionCommand::SetWarnings { warnings, reply } => {
                let res = self.session.set_warnings(warnings).await;
                let _ = reply.send(res);
            }
            SessionCommand::SetContactVerificationWarning { enabled, reply } => {
                let res = self.session.set_contact_verification_warning(enabled).await;
                let _ = reply.send(res);
            }
            SessionCommand::SetManualVerification { enabled, reply } => {
                let res = self.session.set_manual_verification(enabled).await;
                let _ = reply.send(res);
            }
            SessionCommand::KeysDowngradeDetected { reply } => {
                let res = Ok(self.session.keys_downgrade_detected());
                let _ = reply.send(res);
            }
            SessionCommand::ContactVerificationWarning { reply } => {
                let res = Ok(self.session.contact_verification_warning());
                let _ = reply.send(res);
            }
            SessionCommand::AuthringState { handle, reply } => {
                let res = Ok(self.session.authring_state(&handle));
                let _ = reply.send(res);
            }
            SessionCommand::WatchStatus { callback, reply } => {
                self.session.watch_status(callback);
                let _ = reply.send(Ok(()));
            }
            SessionCommand::ChangePassword {
                new_password,
                reply,
            } => {
                let res = self.session.change_password(&new_password).await;
                let _ = reply.send(res);
            }
            SessionCommand::Save { path, reply } => {
                let res = self.session.save(path);
                let _ = reply.send(res);
            }
            SessionCommand::Shutdown { reply } => {
                self.flush_keys_persist_if_dirty(true).await;
                let _ = reply.send(());
                return true;
            }
        }
        self.refresh_runtime_state();
        false
    }
}

fn join_remote_path(remote_parent: &str, name: &str) -> String {
    let trimmed = remote_parent.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", trimmed, name)
    }
}

fn build_target_path(remote_parent: &str, local_path: &str) -> String {
    let file_name = std::path::Path::new(local_path)
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or(local_path);
    join_remote_path(remote_parent, file_name)
}
