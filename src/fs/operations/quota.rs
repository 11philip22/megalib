//! Storage quota operations.

use serde_json::json;

use crate::error::Result;
use crate::fs::node::Quota;
use crate::session::Session;

impl Session {
    /// Get user storage quota.
    pub async fn quota(&mut self) -> Result<Quota> {
        let response = self
            .api_mut()
            .request(json!({"a": "uq", "xfer": 1, "strg": 1}))
            .await?;

        let total = response.get("mstrg").and_then(|v| v.as_u64()).unwrap_or(0);
        let used = response.get("cstrg").and_then(|v| v.as_u64()).unwrap_or(0);

        Ok(Quota { total, used })
    }
}
