use std::collections::{HashMap, HashSet};
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{MegaError, Result};
use crate::fs::upload_state::UploadState;
use crate::fs::{Node, NodeType};

pub(crate) const ENGINE_STATE_SCHEMA_VERSION: u32 = 1;
pub(crate) const SQLITE_PERSISTENCE_BACKEND_SCHEMA_VERSION: u32 = 1;

const SQLITE_META_SCHEMA_VERSION_KEY: &str = "backend_schema_version";
const SQLITE_ENGINE_STATE_SINGLETON_SLOT: i64 = 0;

#[derive(Debug)]
enum SqliteSchemaInitError {
    RecycleRequired(String),
    Fatal(MegaError),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct PersistenceScope {
    pub(crate) account_handle: String,
}

impl PersistenceScope {
    pub(crate) fn new(account_handle: impl Into<String>) -> Self {
        Self {
            account_handle: account_handle.into(),
        }
    }
}

fn default_persistence_root() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = env::var_os("LOCALAPPDATA").ok_or_else(|| {
            MegaError::Custom("LOCALAPPDATA is not set for persistence root resolution".to_string())
        })?;
        return Ok(PathBuf::from(base).join("megalib"));
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").ok_or_else(|| {
            MegaError::Custom("HOME is not set for persistence root resolution".to_string())
        })?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("megalib"))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(xdg_state_home) = env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(xdg_state_home).join("megalib"));
        }

        let home = env::var_os("HOME").ok_or_else(|| {
            MegaError::Custom(
                "HOME is not set for persistence root resolution and XDG_STATE_HOME is absent"
                    .to_string(),
            )
        })?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("megalib"))
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct TransferPersistenceKey {
    pub(crate) kind: TransferPersistenceKind,
    pub(crate) local_fingerprint: String,
}

#[cfg_attr(not(test), allow(dead_code))]
impl TransferPersistenceKey {
    pub(crate) fn upload(local_fingerprint: impl Into<String>) -> Self {
        Self {
            kind: TransferPersistenceKind::Upload,
            local_fingerprint: local_fingerprint.into(),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum TransferPersistenceKind {
    Upload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedEngineState {
    pub(crate) schema_version: u32,
    pub(crate) sc: PersistedScState,
    pub(crate) alerts: PersistedAlertsState,
    pub(crate) tree: Option<PersistedTreeState>,
}

impl PersistedEngineState {
    pub(crate) fn validate_schema_version(&self) -> Result<()> {
        if self.schema_version == ENGINE_STATE_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(MegaError::Custom(format!(
                "Unsupported persistence schema version: {}",
                self.schema_version
            )))
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct PersistedScState {
    pub(crate) scsn: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct PersistedAlertsState {
    pub(crate) alerts_catchup_pending: bool,
    pub(crate) user_alert_lsn: Option<String>,
    pub(crate) user_alerts: Vec<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct PersistedTreeState {
    pub(crate) nodes: Vec<PersistedNodeRecord>,
    pub(crate) pending_nodes: Vec<Value>,
    pub(crate) outshares: HashMap<String, HashSet<String>>,
    pub(crate) pending_outshares: HashMap<String, HashSet<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PersistedNodeRecord {
    pub(crate) name: String,
    pub(crate) handle: String,
    pub(crate) parent_handle: Option<String>,
    pub(crate) node_type: NodeType,
    pub(crate) size: u64,
    pub(crate) timestamp: i64,
    pub(crate) key: Vec<u8>,
    pub(crate) link: Option<String>,
    pub(crate) file_attr: Option<String>,
    pub(crate) share_key: Option<[u8; 16]>,
    pub(crate) share_handle: Option<String>,
    pub(crate) is_inshare: bool,
    pub(crate) is_outshare: bool,
    pub(crate) share_access: Option<i32>,
}

impl From<&Node> for PersistedNodeRecord {
    fn from(node: &Node) -> Self {
        Self {
            name: node.name.clone(),
            handle: node.handle.clone(),
            parent_handle: node.parent_handle.clone(),
            node_type: node.node_type,
            size: node.size,
            timestamp: node.timestamp,
            key: node.key.clone(),
            link: node.link.clone(),
            file_attr: node.file_attr.clone(),
            share_key: node.share_key,
            share_handle: node.share_handle.clone(),
            is_inshare: node.is_inshare,
            is_outshare: node.is_outshare,
            share_access: node.share_access,
        }
    }
}

impl PersistedNodeRecord {
    pub(crate) fn into_node(self) -> Node {
        Node {
            name: self.name,
            handle: self.handle,
            parent_handle: self.parent_handle,
            node_type: self.node_type,
            size: self.size,
            timestamp: self.timestamp,
            key: self.key,
            path: None,
            link: self.link,
            file_attr: self.file_attr,
            share_key: self.share_key,
            share_handle: self.share_handle,
            is_inshare: self.is_inshare,
            is_outshare: self.is_outshare,
            share_access: self.share_access,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct SqlitePersistenceBackend {
    root: PathBuf,
}

#[cfg_attr(not(test), allow(dead_code))]
impl SqlitePersistenceBackend {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn db_path(&self, scope: &PersistenceScope) -> PathBuf {
        self.root.join(format!(
            "acct-{}.sqlite3",
            hex::encode(scope.account_handle.as_bytes())
        ))
    }

    fn open_connection(&self, scope: &PersistenceScope) -> Result<Connection> {
        self.ensure_root_dir()?;
        let path = self.db_path(scope);
        match self.open_connection_once(&path) {
            Ok(mut conn) => match self.ensure_schema(&mut conn, &path) {
                Ok(()) => Ok(conn),
                Err(SqliteSchemaInitError::RecycleRequired(reason)) => {
                    drop(conn);
                    self.recycle_database(&path, &reason)?;
                    let mut recycled = self.open_connection_once(&path)?;
                    self.ensure_schema(&mut recycled, &path)
                        .map_err(Self::schema_init_error_to_mega_error)?;
                    Ok(recycled)
                }
                Err(SqliteSchemaInitError::Fatal(err)) => Err(err),
            },
            Err(err) => Err(err),
        }
    }

    fn ensure_root_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(|err| {
            MegaError::Custom(format!(
                "Failed to create persistence root {}: {}",
                self.root.display(),
                err
            ))
        })
    }

    fn open_connection_once(&self, path: &Path) -> Result<Connection> {
        Connection::open(path).map_err(|err| {
            MegaError::Custom(format!(
                "Failed to open persistence database {}: {}",
                path.display(),
                err
            ))
        })
    }

    fn ensure_schema(
        &self,
        conn: &mut Connection,
        path: &Path,
    ) -> std::result::Result<(), SqliteSchemaInitError> {
        let tx = conn.transaction().map_err(|err| {
            SqliteSchemaInitError::Fatal(MegaError::Custom(format!(
                "Failed to start persistence schema transaction for {}: {}",
                path.display(),
                err
            )))
        })?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS engine_state (
                slot INTEGER PRIMARY KEY CHECK(slot = 0),
                json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS upload_state (
                kind TEXT NOT NULL,
                local_fingerprint TEXT NOT NULL,
                json TEXT NOT NULL,
                PRIMARY KEY(kind, local_fingerprint)
            );",
        )
        .map_err(|err| {
            SqliteSchemaInitError::Fatal(MegaError::Custom(format!(
                "Failed to initialize persistence schema for {}: {}",
                path.display(),
                err
            )))
        })?;

        let existing_schema_version: Option<String> = tx
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [SQLITE_META_SCHEMA_VERSION_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| {
                SqliteSchemaInitError::Fatal(MegaError::Custom(format!(
                    "Failed to read persistence schema version from {}: {}",
                    path.display(),
                    err
                )))
            })?;

        match existing_schema_version {
            Some(version) => {
                let parsed = version.parse::<u32>().map_err(|err| {
                    SqliteSchemaInitError::RecycleRequired(format!(
                        "Invalid persistence backend schema version in {}: {}",
                        path.display(),
                        err
                    ))
                })?;
                if parsed != SQLITE_PERSISTENCE_BACKEND_SCHEMA_VERSION {
                    return Err(SqliteSchemaInitError::RecycleRequired(format!(
                        "Unsupported persistence backend schema version: {}",
                        parsed
                    )));
                }
            }
            None => {
                tx.execute(
                    "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                    params![
                        SQLITE_META_SCHEMA_VERSION_KEY,
                        SQLITE_PERSISTENCE_BACKEND_SCHEMA_VERSION.to_string()
                    ],
                )
                .map_err(|err| {
                    SqliteSchemaInitError::Fatal(MegaError::Custom(format!(
                        "Failed to write persistence schema version to {}: {}",
                        path.display(),
                        err
                    )))
                })?;
            }
        }

        tx.commit().map_err(|err| {
            SqliteSchemaInitError::Fatal(MegaError::Custom(format!(
                "Failed to commit persistence schema transaction for {}: {}",
                path.display(),
                err
            )))
        })?;

        Ok(())
    }

    fn transfer_kind_storage_value(kind: &TransferPersistenceKind) -> &'static str {
        match kind {
            TransferPersistenceKind::Upload => "upload",
        }
    }

    fn recycle_database(&self, path: &Path, reason: &str) -> Result<()> {
        if !path.exists() {
            return Ok(());
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let recycled_path = path.with_extension(format!("sqlite3.recycled-{timestamp}"));

        fs::rename(path, &recycled_path).map_err(|err| {
            MegaError::Custom(format!(
                "Failed to recycle persistence database {} after {}: {}",
                path.display(),
                reason,
                err
            ))
        })
    }

    fn schema_init_error_to_mega_error(err: SqliteSchemaInitError) -> MegaError {
        match err {
            SqliteSchemaInitError::RecycleRequired(reason) => MegaError::Custom(reason),
            SqliteSchemaInitError::Fatal(err) => err,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) trait PersistenceBackend: Send + Sync {
    fn load_engine_state(&self, scope: &PersistenceScope) -> Result<Option<PersistedEngineState>>;
    fn save_engine_state(
        &self,
        scope: &PersistenceScope,
        state: &PersistedEngineState,
    ) -> Result<()>;
    fn clear_engine_state(&self, scope: &PersistenceScope) -> Result<()>;

    fn load_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<Option<UploadState>>;
    fn save_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
        state: &UploadState,
    ) -> Result<()>;
    fn clear_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<()>;
}

#[derive(Clone)]
pub(crate) struct PersistenceRuntime {
    backend: Arc<dyn PersistenceBackend>,
}

impl fmt::Debug for PersistenceRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistenceRuntime").finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))]
impl PersistenceRuntime {
    pub(crate) fn disabled() -> Self {
        Self::new(Arc::new(NoopPersistenceBackend))
    }

    pub(crate) fn production_default() -> Result<Self> {
        Ok(Self::production_at(default_persistence_root()?))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn production_at(root: PathBuf) -> Self {
        Self::new(Arc::new(SqlitePersistenceBackend::new(root)))
    }

    pub(crate) fn new(backend: Arc<dyn PersistenceBackend>) -> Self {
        Self { backend }
    }

    pub(crate) fn load_engine_state(
        &self,
        scope: &PersistenceScope,
    ) -> Result<Option<PersistedEngineState>> {
        let state = self.backend.load_engine_state(scope)?;
        if let Some(state) = state {
            state.validate_schema_version()?;
            Ok(Some(state))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn save_engine_state(
        &self,
        scope: &PersistenceScope,
        state: &PersistedEngineState,
    ) -> Result<()> {
        state.validate_schema_version()?;
        self.backend.save_engine_state(scope, state)
    }

    pub(crate) fn clear_engine_state(&self, scope: &PersistenceScope) -> Result<()> {
        self.backend.clear_engine_state(scope)
    }

    pub(crate) fn load_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<Option<UploadState>> {
        self.backend.load_upload_state(scope, key)
    }

    pub(crate) fn save_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
        state: &UploadState,
    ) -> Result<()> {
        self.backend.save_upload_state(scope, key, state)
    }

    pub(crate) fn clear_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<()> {
        self.backend.clear_upload_state(scope, key)
    }
}

#[derive(Debug, Default)]
pub(crate) struct NoopPersistenceBackend;

impl PersistenceBackend for NoopPersistenceBackend {
    fn load_engine_state(&self, _scope: &PersistenceScope) -> Result<Option<PersistedEngineState>> {
        Ok(None)
    }

    fn save_engine_state(
        &self,
        _scope: &PersistenceScope,
        _state: &PersistedEngineState,
    ) -> Result<()> {
        Ok(())
    }

    fn clear_engine_state(&self, _scope: &PersistenceScope) -> Result<()> {
        Ok(())
    }

    fn load_upload_state(
        &self,
        _scope: &PersistenceScope,
        _key: &TransferPersistenceKey,
    ) -> Result<Option<UploadState>> {
        Ok(None)
    }

    fn save_upload_state(
        &self,
        _scope: &PersistenceScope,
        _key: &TransferPersistenceKey,
        _state: &UploadState,
    ) -> Result<()> {
        Ok(())
    }

    fn clear_upload_state(
        &self,
        _scope: &PersistenceScope,
        _key: &TransferPersistenceKey,
    ) -> Result<()> {
        Ok(())
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Default)]
pub(crate) struct MemoryPersistenceBackend {
    engine_states: Mutex<HashMap<PersistenceScope, PersistedEngineState>>,
    upload_states: Mutex<HashMap<(PersistenceScope, TransferPersistenceKey), UploadState>>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl MemoryPersistenceBackend {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn lock_engine_states(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<PersistenceScope, PersistedEngineState>>> {
        self.engine_states
            .lock()
            .map_err(|_| MegaError::Custom("engine state memory store is poisoned".to_string()))
    }

    fn lock_upload_states(
        &self,
    ) -> Result<
        std::sync::MutexGuard<'_, HashMap<(PersistenceScope, TransferPersistenceKey), UploadState>>,
    > {
        self.upload_states
            .lock()
            .map_err(|_| MegaError::Custom("upload state memory store is poisoned".to_string()))
    }
}

impl PersistenceBackend for MemoryPersistenceBackend {
    fn load_engine_state(&self, scope: &PersistenceScope) -> Result<Option<PersistedEngineState>> {
        Ok(self.lock_engine_states()?.get(scope).cloned())
    }

    fn save_engine_state(
        &self,
        scope: &PersistenceScope,
        state: &PersistedEngineState,
    ) -> Result<()> {
        self.lock_engine_states()?
            .insert(scope.clone(), state.clone());
        Ok(())
    }

    fn clear_engine_state(&self, scope: &PersistenceScope) -> Result<()> {
        self.lock_engine_states()?.remove(scope);
        Ok(())
    }

    fn load_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<Option<UploadState>> {
        Ok(self
            .lock_upload_states()?
            .get(&(scope.clone(), key.clone()))
            .cloned())
    }

    fn save_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
        state: &UploadState,
    ) -> Result<()> {
        self.lock_upload_states()?
            .insert((scope.clone(), key.clone()), state.clone());
        Ok(())
    }

    fn clear_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<()> {
        self.lock_upload_states()?
            .remove(&(scope.clone(), key.clone()));
        Ok(())
    }
}

impl PersistenceBackend for SqlitePersistenceBackend {
    fn load_engine_state(&self, scope: &PersistenceScope) -> Result<Option<PersistedEngineState>> {
        let conn = self.open_connection(scope)?;
        let db_path = self.db_path(scope);
        let json: Option<String> = conn
            .query_row(
                "SELECT json FROM engine_state WHERE slot = ?1",
                [SQLITE_ENGINE_STATE_SINGLETON_SLOT],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| {
                MegaError::Custom(format!(
                    "Failed to load engine state from {}: {}",
                    db_path.display(),
                    err
                ))
            })?;

        match json {
            Some(json) => match serde_json::from_str(&json) {
                Ok(state) => Ok(Some(state)),
                Err(_) => {
                    conn.execute(
                        "DELETE FROM engine_state WHERE slot = ?1",
                        [SQLITE_ENGINE_STATE_SINGLETON_SLOT],
                    )
                    .map_err(|err| {
                        MegaError::Custom(format!(
                            "Failed to clear malformed engine state from {}: {}",
                            db_path.display(),
                            err
                        ))
                    })?;
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    fn save_engine_state(
        &self,
        scope: &PersistenceScope,
        state: &PersistedEngineState,
    ) -> Result<()> {
        let conn = self.open_connection(scope)?;
        let json = serde_json::to_string(state)?;
        conn.execute(
            "INSERT INTO engine_state (slot, json) VALUES (?1, ?2)
             ON CONFLICT(slot) DO UPDATE SET json = excluded.json",
            params![SQLITE_ENGINE_STATE_SINGLETON_SLOT, json],
        )
        .map_err(|err| {
            MegaError::Custom(format!(
                "Failed to save engine state to {}: {}",
                self.db_path(scope).display(),
                err
            ))
        })?;
        Ok(())
    }

    fn clear_engine_state(&self, scope: &PersistenceScope) -> Result<()> {
        let conn = self.open_connection(scope)?;
        conn.execute(
            "DELETE FROM engine_state WHERE slot = ?1",
            [SQLITE_ENGINE_STATE_SINGLETON_SLOT],
        )
        .map_err(|err| {
            MegaError::Custom(format!(
                "Failed to clear engine state from {}: {}",
                self.db_path(scope).display(),
                err
            ))
        })?;
        Ok(())
    }

    fn load_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<Option<UploadState>> {
        let conn = self.open_connection(scope)?;
        let db_path = self.db_path(scope);
        let json: Option<String> = conn
            .query_row(
                "SELECT json FROM upload_state
                 WHERE kind = ?1 AND local_fingerprint = ?2",
                params![
                    Self::transfer_kind_storage_value(&key.kind),
                    key.local_fingerprint
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| {
                MegaError::Custom(format!(
                    "Failed to load upload state from {}: {}",
                    db_path.display(),
                    err
                ))
            })?;

        match json {
            Some(json) => match serde_json::from_str(&json) {
                Ok(state) => Ok(Some(state)),
                Err(_) => {
                    conn.execute(
                        "DELETE FROM upload_state WHERE kind = ?1 AND local_fingerprint = ?2",
                        params![
                            Self::transfer_kind_storage_value(&key.kind),
                            key.local_fingerprint
                        ],
                    )
                    .map_err(|err| {
                        MegaError::Custom(format!(
                            "Failed to clear malformed upload state from {}: {}",
                            db_path.display(),
                            err
                        ))
                    })?;
                    Ok(None)
                }
            },
            None => Ok(None),
        }
    }

    fn save_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
        state: &UploadState,
    ) -> Result<()> {
        let conn = self.open_connection(scope)?;
        let json = serde_json::to_string(state)?;
        conn.execute(
            "INSERT INTO upload_state (kind, local_fingerprint, json) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, local_fingerprint) DO UPDATE SET json = excluded.json",
            params![
                Self::transfer_kind_storage_value(&key.kind),
                key.local_fingerprint,
                json
            ],
        )
        .map_err(|err| {
            MegaError::Custom(format!(
                "Failed to save upload state to {}: {}",
                self.db_path(scope).display(),
                err
            ))
        })?;
        Ok(())
    }

    fn clear_upload_state(
        &self,
        scope: &PersistenceScope,
        key: &TransferPersistenceKey,
    ) -> Result<()> {
        let conn = self.open_connection(scope)?;
        conn.execute(
            "DELETE FROM upload_state WHERE kind = ?1 AND local_fingerprint = ?2",
            params![
                Self::transfer_kind_storage_value(&key.kind),
                key.local_fingerprint
            ],
        )
        .map_err(|err| {
            MegaError::Custom(format!(
                "Failed to clear upload state from {}: {}",
                self.db_path(scope).display(),
                err
            ))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Node;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "megalib-persistence-{}-{}-{}",
                label,
                std::process::id(),
                unique
            ));
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn sample_scope() -> PersistenceScope {
        PersistenceScope::new("account-handle")
    }

    fn sample_engine_state() -> PersistedEngineState {
        PersistedEngineState {
            schema_version: ENGINE_STATE_SCHEMA_VERSION,
            sc: PersistedScState {
                scsn: Some("scsn-123".to_string()),
            },
            alerts: PersistedAlertsState {
                alerts_catchup_pending: true,
                user_alert_lsn: Some("lsn-123".to_string()),
                user_alerts: vec![serde_json::json!({"id": 1})],
            },
            tree: None,
        }
    }

    fn sample_upload_state() -> UploadState {
        UploadState::new(
            "https://example.invalid/upload".to_string(),
            [1u8; 16],
            [2u8; 8],
            1024,
            "example.bin".to_string(),
            "parent-handle".to_string(),
            "fingerprint".to_string(),
        )
    }

    fn sample_node() -> Node {
        Node {
            name: "example.txt".to_string(),
            handle: "node-handle".to_string(),
            parent_handle: Some("parent-handle".to_string()),
            node_type: NodeType::File,
            size: 1024,
            timestamp: 12345,
            key: vec![1, 2, 3, 4],
            path: Some("/Root/example.txt".to_string()),
            link: Some("public-link".to_string()),
            file_attr: Some("924:1*thumb".to_string()),
            share_key: Some([7u8; 16]),
            share_handle: Some("share-root".to_string()),
            is_inshare: true,
            is_outshare: false,
            share_access: Some(1),
        }
    }

    fn sqlite_backend(label: &str) -> (TestDir, SqlitePersistenceBackend) {
        let dir = TestDir::new(label);
        let backend = SqlitePersistenceBackend::new(dir.path().to_path_buf());
        (dir, backend)
    }

    #[test]
    fn disabled_runtime_behaves_like_empty_store() {
        let runtime = PersistenceRuntime::disabled();
        let scope = sample_scope();
        let key = TransferPersistenceKey::upload("file-fingerprint");

        assert!(
            runtime
                .load_engine_state(&scope)
                .expect("load engine state should succeed")
                .is_none()
        );
        assert!(
            runtime
                .load_upload_state(&scope, &key)
                .expect("load upload state should succeed")
                .is_none()
        );
        runtime
            .save_engine_state(&scope, &sample_engine_state())
            .expect("save engine state should succeed");
        runtime
            .save_upload_state(&scope, &key, &sample_upload_state())
            .expect("save upload state should succeed");
        runtime
            .clear_engine_state(&scope)
            .expect("clear engine state should succeed");
        runtime
            .clear_upload_state(&scope, &key)
            .expect("clear upload state should succeed");
    }

    #[test]
    fn memory_backend_round_trips_engine_and_upload_state() {
        let runtime = PersistenceRuntime::new(Arc::new(MemoryPersistenceBackend::new()));
        let scope = sample_scope();
        let key = TransferPersistenceKey::upload("file-fingerprint");
        let engine_state = sample_engine_state();
        let upload_state = sample_upload_state();

        runtime
            .save_engine_state(&scope, &engine_state)
            .expect("save engine state should succeed");
        runtime
            .save_upload_state(&scope, &key, &upload_state)
            .expect("save upload state should succeed");

        let loaded_engine_state = runtime
            .load_engine_state(&scope)
            .expect("load engine state should succeed")
            .expect("engine state should exist");
        let loaded_upload_state = runtime
            .load_upload_state(&scope, &key)
            .expect("load upload state should succeed")
            .expect("upload state should exist");

        assert_eq!(loaded_engine_state.sc.scsn.as_deref(), Some("scsn-123"));
        assert_eq!(
            loaded_engine_state.alerts.user_alert_lsn.as_deref(),
            Some("lsn-123")
        );
        assert_eq!(loaded_engine_state.alerts.user_alerts.len(), 1);
        assert_eq!(loaded_upload_state.upload_url, upload_state.upload_url);
        assert_eq!(loaded_upload_state.file_hash, upload_state.file_hash);

        runtime
            .clear_engine_state(&scope)
            .expect("clear engine state should succeed");
        runtime
            .clear_upload_state(&scope, &key)
            .expect("clear upload state should succeed");

        assert!(
            runtime
                .load_engine_state(&scope)
                .expect("load engine state after clear should succeed")
                .is_none()
        );
        assert!(
            runtime
                .load_upload_state(&scope, &key)
                .expect("load upload state after clear should succeed")
                .is_none()
        );
    }

    #[test]
    fn runtime_rejects_unsupported_schema_version() {
        let runtime = PersistenceRuntime::new(Arc::new(MemoryPersistenceBackend::new()));
        let scope = sample_scope();
        let mut engine_state = sample_engine_state();
        engine_state.schema_version = ENGINE_STATE_SCHEMA_VERSION + 1;

        let err = runtime
            .save_engine_state(&scope, &engine_state)
            .expect_err("save should reject unsupported schema version");

        assert!(
            err.to_string()
                .contains("Unsupported persistence schema version")
        );
    }

    #[test]
    fn memory_backend_scope_isolation_is_preserved() {
        let runtime = PersistenceRuntime::new(Arc::new(MemoryPersistenceBackend::new()));
        let scope_a = PersistenceScope::new("account-a");
        let scope_b = PersistenceScope::new("account-b");

        runtime
            .save_engine_state(&scope_a, &sample_engine_state())
            .expect("save for scope A should succeed");

        assert!(
            runtime
                .load_engine_state(&scope_b)
                .expect("load for scope B should succeed")
                .is_none()
        );
    }

    #[test]
    fn persisted_node_record_round_trips_runtime_fields_except_path() {
        let node = sample_node();

        let record = PersistedNodeRecord::from(&node);
        let restored = record.into_node();

        assert_eq!(restored.name, node.name);
        assert_eq!(restored.handle, node.handle);
        assert_eq!(restored.parent_handle, node.parent_handle);
        assert_eq!(restored.node_type, node.node_type);
        assert_eq!(restored.size, node.size);
        assert_eq!(restored.timestamp, node.timestamp);
        assert_eq!(restored.key, node.key);
        assert_eq!(restored.link, node.link);
        assert_eq!(restored.file_attr, node.file_attr);
        assert_eq!(restored.share_key, node.share_key);
        assert_eq!(restored.share_handle, node.share_handle);
        assert_eq!(restored.is_inshare, node.is_inshare);
        assert_eq!(restored.is_outshare, node.is_outshare);
        assert_eq!(restored.share_access, node.share_access);
        assert_eq!(restored.path, None);
    }

    #[test]
    fn sqlite_backend_round_trips_engine_and_upload_state() {
        let (_dir, backend) = sqlite_backend("roundtrip");
        let scope = sample_scope();
        let key = TransferPersistenceKey::upload("file-fingerprint");
        let engine_state = sample_engine_state();
        let upload_state = sample_upload_state();

        backend
            .save_engine_state(&scope, &engine_state)
            .expect("sqlite backend should save engine state");
        backend
            .save_upload_state(&scope, &key, &upload_state)
            .expect("sqlite backend should save upload state");

        let reloaded = SqlitePersistenceBackend::new(backend.root.clone());

        let loaded_engine_state = reloaded
            .load_engine_state(&scope)
            .expect("sqlite backend should load engine state")
            .expect("engine state should exist");
        let loaded_upload_state = reloaded
            .load_upload_state(&scope, &key)
            .expect("sqlite backend should load upload state")
            .expect("upload state should exist");

        assert_eq!(loaded_engine_state.sc.scsn, engine_state.sc.scsn);
        assert_eq!(
            loaded_engine_state.alerts.user_alert_lsn,
            engine_state.alerts.user_alert_lsn
        );
        assert_eq!(loaded_upload_state.upload_url, upload_state.upload_url);
        assert_eq!(loaded_upload_state.file_hash, upload_state.file_hash);
    }

    #[test]
    fn sqlite_backend_uses_scope_qualified_db_paths() {
        let (_dir, backend) = sqlite_backend("scope-paths");
        let scope_a = PersistenceScope::new("account-a");
        let scope_b = PersistenceScope::new("account-b");

        let path_a = backend.db_path(&scope_a);
        let path_b = backend.db_path(&scope_b);

        assert_ne!(path_a, path_b);
        assert!(path_a.starts_with(&backend.root));
        assert!(path_b.starts_with(&backend.root));
        assert_eq!(
            path_a.extension().and_then(|ext| ext.to_str()),
            Some("sqlite3")
        );
        assert_eq!(
            path_b.extension().and_then(|ext| ext.to_str()),
            Some("sqlite3")
        );
    }

    #[test]
    fn sqlite_backend_initializes_schema_on_first_write() {
        let (_dir, backend) = sqlite_backend("schema-init");
        let scope = sample_scope();
        let db_path = backend.db_path(&scope);

        assert!(!db_path.exists());

        backend
            .save_engine_state(&scope, &sample_engine_state())
            .expect("sqlite backend should initialize schema during first save");

        assert!(db_path.exists());
    }

    #[test]
    fn sqlite_backend_recycles_unsupported_backend_schema_version() {
        let (_dir, backend) = sqlite_backend("schema-version");
        let scope = sample_scope();

        backend
            .save_engine_state(&scope, &sample_engine_state())
            .expect("initial save should succeed");

        let conn = Connection::open(backend.db_path(&scope))
            .expect("test should be able to reopen sqlite database");
        conn.execute(
            "UPDATE meta SET value = ?1 WHERE key = ?2",
            params!["999", SQLITE_META_SCHEMA_VERSION_KEY],
        )
        .expect("test should be able to mutate schema version");

        let loaded = backend
            .load_engine_state(&scope)
            .expect("unsupported backend schema should recycle cleanly");

        assert!(loaded.is_none());
        assert!(backend.db_path(&scope).exists());
    }

    #[test]
    fn sqlite_backend_treats_malformed_engine_state_as_cache_miss() {
        let (_dir, backend) = sqlite_backend("malformed-engine");
        let scope = sample_scope();

        backend
            .save_engine_state(&scope, &sample_engine_state())
            .expect("initial save should succeed");

        let conn = Connection::open(backend.db_path(&scope))
            .expect("test should be able to reopen sqlite database");
        conn.execute(
            "UPDATE engine_state SET json = ?1 WHERE slot = ?2",
            params!["{not-json", SQLITE_ENGINE_STATE_SINGLETON_SLOT],
        )
        .expect("test should be able to corrupt engine state row");

        let loaded = backend
            .load_engine_state(&scope)
            .expect("malformed engine state should be treated as cache miss");

        assert!(loaded.is_none());
    }

    #[test]
    fn sqlite_backend_treats_malformed_upload_state_as_cache_miss() {
        let (_dir, backend) = sqlite_backend("malformed-upload");
        let scope = sample_scope();
        let key = TransferPersistenceKey::upload("file-fingerprint");

        backend
            .save_upload_state(&scope, &key, &sample_upload_state())
            .expect("initial save should succeed");

        let conn = Connection::open(backend.db_path(&scope))
            .expect("test should be able to reopen sqlite database");
        conn.execute(
            "UPDATE upload_state SET json = ?1 WHERE kind = ?2 AND local_fingerprint = ?3",
            params![
                "{not-json",
                SqlitePersistenceBackend::transfer_kind_storage_value(&key.kind),
                key.local_fingerprint
            ],
        )
        .expect("test should be able to corrupt upload state row");

        let loaded = backend
            .load_upload_state(&scope, &key)
            .expect("malformed upload state should be treated as cache miss");

        assert!(loaded.is_none());
    }

    #[test]
    fn production_runtime_uses_sqlite_backend_round_trip() {
        let dir = TestDir::new("production-runtime");
        let runtime = PersistenceRuntime::production_at(dir.path().to_path_buf());
        let scope = sample_scope();
        let state = sample_engine_state();

        runtime
            .save_engine_state(&scope, &state)
            .expect("production runtime should save engine state");

        let loaded = runtime
            .load_engine_state(&scope)
            .expect("production runtime should load engine state")
            .expect("engine state should exist");

        assert_eq!(loaded.sc.scsn, state.sc.scsn);
    }
}
