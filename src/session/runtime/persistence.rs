use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{MegaError, Result};
use crate::fs::NodeType;
use crate::fs::upload_state::UploadState;

pub(crate) const ENGINE_STATE_SCHEMA_VERSION: u32 = 1;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
