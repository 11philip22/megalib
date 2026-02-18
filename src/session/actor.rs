//! Actor-based session runtime for background SC polling.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use futures::io::{AsyncRead, AsyncSeek};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep};

use crate::crypto::{AuthState, Warnings};
use crate::error::{MegaError, Result};
use crate::fs::{Node, Quota};
use crate::progress::ProgressCallback;
use crate::session::core::{FolderSessionBlob, Session, SessionBlob};

trait AsyncReadSeek: AsyncRead + AsyncSeek + Unpin + Send {}

impl<T> AsyncReadSeek for T where T: AsyncRead + AsyncSeek + Unpin + Send {}

type BoxedReader = Box<dyn AsyncReadSeek>;
type BoxedWriter = Box<dyn Write + Send>;
type SeqtagWaiter = Box<dyn FnOnce(&mut Session) + Send>;

#[derive(Debug, Clone)]
pub struct AccountInfo {
    pub email: String,
    pub name: Option<String>,
    pub user_handle: String,
    pub session_id: String,
}

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
    seqtag_waiters: HashMap<String, Vec<SeqtagWaiter>>,
    alerts_enabled: bool,
    alerts_inflight: bool,
}

impl SessionHandle {
    pub fn parse_session_blob(session_b64: &str) -> Result<SessionBlob> {
        Session::parse_session_blob(session_b64)
    }

    pub fn parse_folder_session_blob(session_b64: &str) -> Result<FolderSessionBlob> {
        Session::parse_folder_session_blob(session_b64)
    }

    pub fn dump_folder_session_blob(blob: &FolderSessionBlob) -> Result<String> {
        Session::dump_folder_session_blob(blob)
    }

    pub async fn login(email: &str, password: &str) -> Result<Self> {
        let session = Session::login(email, password).await?;
        Ok(SessionActor::spawn(session))
    }

    pub async fn login_with_proxy(email: &str, password: &str, proxy: &str) -> Result<Self> {
        let session = Session::login_with_proxy(email, password, proxy).await?;
        Ok(SessionActor::spawn(session))
    }

    pub async fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Option<Self>> {
        let session = Session::load(path).await?;
        Ok(session.map(SessionActor::spawn))
    }

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

    pub async fn account_info(&self) -> Result<AccountInfo> {
        self.request(|reply| SessionCommand::AccountInfo { reply })
            .await
    }

    pub async fn dump_session(&self) -> Result<String> {
        self.request(|reply| SessionCommand::DumpSession { reply })
            .await
    }

    pub async fn dump_session_blob(&self) -> Result<Vec<u8>> {
        self.request(|reply| SessionCommand::DumpSessionBlob { reply })
            .await
    }

    pub async fn refresh(&self) -> Result<()> {
        self.request(|reply| SessionCommand::Refresh { reply })
            .await
    }

    pub async fn quota(&self) -> Result<Quota> {
        self.request(|reply| SessionCommand::Quota { reply }).await
    }

    pub async fn list(&self, path: &str, recursive: bool) -> Result<Vec<Node>> {
        self.request(|reply| SessionCommand::List {
            path: path.to_string(),
            recursive,
            reply,
        })
        .await
    }

    pub async fn stat(&self, path: &str) -> Result<Option<Node>> {
        self.request(|reply| SessionCommand::Stat {
            path: path.to_string(),
            reply,
        })
        .await
    }

    pub async fn nodes(&self) -> Result<Vec<Node>> {
        self.request(|reply| SessionCommand::Nodes { reply }).await
    }

    pub async fn list_contacts(&self) -> Result<Vec<Node>> {
        self.request(|reply| SessionCommand::ListContacts { reply })
            .await
    }

    pub async fn get_node_by_handle(&self, handle: &str) -> Result<Option<Node>> {
        self.request(|reply| SessionCommand::GetNodeByHandle {
            handle: handle.to_string(),
            reply,
        })
        .await
    }

    pub async fn node_has_ancestor(&self, node: &Node, ancestor: &Node) -> Result<bool> {
        self.request(|reply| SessionCommand::NodeHasAncestor {
            node_handle: node.handle.clone(),
            ancestor_handle: ancestor.handle.clone(),
            reply,
        })
        .await
    }

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

    pub async fn mkdir(&self, path: &str) -> Result<Node> {
        self.request(|reply| SessionCommand::Mkdir {
            path: path.to_string(),
            reply,
        })
        .await
    }

    pub async fn mv(&self, source: &str, dest: &str) -> Result<()> {
        self.request(|reply| SessionCommand::Mv {
            source: source.to_string(),
            dest: dest.to_string(),
            reply,
        })
        .await
    }

    pub async fn rename(&self, path: &str, new_name: &str) -> Result<()> {
        self.request(|reply| SessionCommand::Rename {
            path: path.to_string(),
            new_name: new_name.to_string(),
            reply,
        })
        .await
    }

    pub async fn rm(&self, path: &str) -> Result<()> {
        self.request(|reply| SessionCommand::Rm {
            path: path.to_string(),
            reply,
        })
        .await
    }

    pub async fn export(&self, path: &str) -> Result<String> {
        self.request(|reply| SessionCommand::Export {
            path: path.to_string(),
            reply,
        })
        .await
    }

    pub async fn export_many(&self, paths: &[&str]) -> Result<Vec<(String, String)>> {
        self.request(|reply| SessionCommand::ExportMany {
            paths: paths.iter().map(|p| p.to_string()).collect(),
            reply,
        })
        .await
    }

    pub async fn share_folder(&self, handle: &str, email: &str, level: i32) -> Result<()> {
        self.request(|reply| SessionCommand::ShareFolder {
            handle: handle.to_string(),
            email: email.to_string(),
            level,
            reply,
        })
        .await
    }

    pub async fn upload(&self, local: &str, remote: &str) -> Result<Node> {
        self.request(|reply| SessionCommand::Upload {
            local: local.to_string(),
            remote: remote.to_string(),
            reply,
        })
        .await
    }

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

    pub async fn upload_resumable(&self, local: &str, remote_parent: &str) -> Result<Node> {
        self.request(|reply| SessionCommand::UploadResumable {
            local: local.to_string(),
            remote_parent: remote_parent.to_string(),
            reply,
        })
        .await
    }

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

    pub async fn download_to_writer(&self, node: &Node, writer: BoxedWriter) -> Result<()> {
        self.download_to_writer_with_offset(node, writer, 0).await
    }

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

    pub async fn set_workers(&self, workers: usize) -> Result<()> {
        self.request(|reply| SessionCommand::SetWorkers { workers, reply })
            .await
    }

    pub async fn set_resume(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::SetResume { enabled, reply })
            .await
    }

    pub async fn clear_status(&self) -> Result<()> {
        self.request(|reply| SessionCommand::ClearStatus { reply })
            .await
    }

    pub async fn enable_previews(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::EnablePreviews { enabled, reply })
            .await
    }

    pub async fn set_authring_ed25519(&self, blob: Vec<u8>) -> Result<()> {
        self.request(|reply| SessionCommand::SetAuthringEd25519 { blob, reply })
            .await
    }

    pub async fn set_authring_cu25519(&self, blob: Vec<u8>) -> Result<()> {
        self.request(|reply| SessionCommand::SetAuthringCu25519 { blob, reply })
            .await
    }

    pub async fn set_backups_blob(&self, blob: Vec<u8>) -> Result<()> {
        self.request(|reply| SessionCommand::SetBackupsBlob { blob, reply })
            .await
    }

    pub async fn set_warnings(&self, warnings: Warnings) -> Result<()> {
        self.request(|reply| SessionCommand::SetWarnings { warnings, reply })
            .await
    }

    pub async fn set_contact_verification_warning(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::SetContactVerificationWarning { enabled, reply })
            .await
    }

    pub async fn set_manual_verification(&self, enabled: bool) -> Result<()> {
        self.request(|reply| SessionCommand::SetManualVerification { enabled, reply })
            .await
    }

    pub async fn keys_downgrade_detected(&self) -> Result<bool> {
        self.request(|reply| SessionCommand::KeysDowngradeDetected { reply })
            .await
    }

    pub async fn contact_verification_warning(&self) -> Result<bool> {
        self.request(|reply| SessionCommand::ContactVerificationWarning { reply })
            .await
    }

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

    pub async fn watch_status(&self, callback: ProgressCallback) -> Result<()> {
        self.request(|reply| SessionCommand::WatchStatus { callback, reply })
            .await
    }

    pub async fn change_password(&self, new_password: &str) -> Result<()> {
        self.request(|reply| SessionCommand::ChangePassword {
            new_password: new_password.to_string(),
            reply,
        })
        .await
    }

    pub async fn save<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        self.request(|reply| SessionCommand::Save {
            path: path.as_ref().to_path_buf(),
            reply,
        })
        .await
    }

    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(SessionCommand::Shutdown { reply: tx }).await;
        let _ = rx.await;
    }
}

impl SessionActor {
    fn spawn(session: Session) -> SessionHandle {
        let (tx, rx) = mpsc::channel(64);
        let actor = SessionActor {
            session,
            rx,
            seqtag_waiters: HashMap::new(),
            alerts_enabled: true,
            alerts_inflight: false,
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

    async fn run(mut self) {
        let mut delay = Duration::from_millis(1_000);
        let max_delay = Duration::from_millis(60_000);
        let mut next_poll = Instant::now() + delay;

        loop {
            tokio::select! {
                cmd = self.rx.recv() => {
                    let Some(cmd) = cmd else { break; };
                    if self.handle_command(cmd).await {
                        break;
                    }
                }
                _ = sleep(next_poll.saturating_duration_since(Instant::now())) => {
                    if self.session.scsn.is_some() {
                        let poll = tokio::time::timeout(Duration::from_secs(20), self.session.poll_action_packets_once_with_seqtags()).await;
                        match poll {
                            Ok(Ok((_, seqtags))) => {
                                if !seqtags.is_empty() {
                                    self.resolve_seqtag_waiters(&seqtags);
                                }
                                delay = Duration::from_millis(1_000);
                            }
                            Ok(Err(MegaError::ServerBusy)) | Ok(Err(MegaError::InvalidResponse)) | Err(_) => {
                                delay = (delay * 2).min(max_delay);
                            }
                            Ok(Err(_)) => {
                                delay = (delay * 2).min(max_delay);
                            }
                        }
                    }
                    if self.alerts_enabled
                        && !self.session.sc_catchup
                        && self.session.alerts_catchup_pending
                        && !self.alerts_inflight
                    {
                        self.alerts_inflight = true;
                        let _ = self.session.poll_user_alerts_once().await;
                        self.alerts_inflight = false;
                    }
                    next_poll = Instant::now() + delay;
                }
            }
        }
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.mkdir(&path).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.mv(&source, &dest).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.rename(&path, &new_name).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.rm(&path).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.export(&path).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let path_refs: Vec<&str> = paths.iter().map(|p| p.as_str()).collect();
                let res = self.session.export_many(&path_refs).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.share_folder(&handle, &email, level).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.upload(&local, &remote).await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self
                    .session
                    .upload_from_bytes(&data, &filename, &remote)
                    .await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self
                    .session
                    .upload_from_reader(reader, &filename, size, &remote)
                    .await;
                self.session.defer_seqtag_wait = prev;
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
                let prev = self.session.defer_seqtag_wait;
                self.session.defer_seqtag_wait = true;
                let res = self.session.upload_resumable(&local, &remote_parent).await;
                self.session.defer_seqtag_wait = prev;
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
                let _ = reply.send(());
                return true;
            }
        }
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
