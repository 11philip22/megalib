//! Storage quota operations.

use serde_json::json;

use crate::error::Result;
use crate::fs::node::Quota;
use crate::session::Session;
use crate::session::runtime::request::RequestClass;

impl Session {
    /// Get user storage quota.
    pub async fn quota(&mut self) -> Result<Quota> {
        let response = self
            .submit_request_single(
                RequestClass::ReadOnly,
                json!({"a": "uq", "xfer": 1, "strg": 1}),
            )
            .await?;

        let total = response
            .response
            .get("mstrg")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let used = response
            .response
            .get("cstrg")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        Ok(Quota { total, used })
    }
}
