use serde_json::Value;

use crate::api::ApiClient;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestClass {
    ReadOnly,
    Mutating,
}

impl RequestClass {
    fn extracts_seqtag(self) -> bool {
        matches!(self, Self::Mutating)
    }
}

#[derive(Debug)]
pub(crate) enum RequestEnvelope {
    Single {
        class: RequestClass,
        payload: Value,
    },
    Batch {
        class: RequestClass,
        payloads: Vec<Value>,
    },
}

impl RequestEnvelope {
    pub(crate) fn read(payload: Value) -> Self {
        Self::Single {
            class: RequestClass::ReadOnly,
            payload,
        }
    }

    pub(crate) fn mutating(payload: Value) -> Self {
        Self::Single {
            class: RequestClass::Mutating,
            payload,
        }
    }

    pub(crate) fn read_batch(payloads: Vec<Value>) -> Self {
        Self::Batch {
            class: RequestClass::ReadOnly,
            payloads,
        }
    }

    pub(crate) fn mutating_batch(payloads: Vec<Value>) -> Self {
        Self::Batch {
            class: RequestClass::Mutating,
            payloads,
        }
    }
}

#[derive(Debug)]
pub(crate) struct RequestOutcome {
    pub(crate) response: Value,
    pub(crate) seqtag: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct RequestRuntime;

impl RequestRuntime {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) async fn submit(
        &mut self,
        api: &mut ApiClient,
        envelope: RequestEnvelope,
    ) -> Result<RequestOutcome> {
        match envelope {
            RequestEnvelope::Single { class, payload } => {
                let response = api.request(payload).await?;
                let seqtag = class
                    .extracts_seqtag()
                    .then(|| Self::extract_seqtag(&response))
                    .flatten();
                Ok(RequestOutcome { response, seqtag })
            }
            RequestEnvelope::Batch { class, payloads } => {
                if payloads.is_empty() {
                    return Ok(RequestOutcome {
                        response: Value::Array(vec![]),
                        seqtag: None,
                    });
                }

                let response = api.request_batch(payloads).await?;
                let seqtag = class
                    .extracts_seqtag()
                    .then(|| Self::extract_seqtag(&response))
                    .flatten();
                Ok(RequestOutcome { response, seqtag })
            }
        }
    }

    pub(crate) async fn submit_single(
        &mut self,
        api: &mut ApiClient,
        class: RequestClass,
        payload: Value,
    ) -> Result<RequestOutcome> {
        let envelope = match class {
            RequestClass::ReadOnly => RequestEnvelope::read(payload),
            RequestClass::Mutating => RequestEnvelope::mutating(payload),
        };
        self.submit(api, envelope).await
    }

    pub(crate) async fn submit_batch(
        &mut self,
        api: &mut ApiClient,
        class: RequestClass,
        payloads: Vec<Value>,
    ) -> Result<RequestOutcome> {
        let envelope = match class {
            RequestClass::ReadOnly => RequestEnvelope::read_batch(payloads),
            RequestClass::Mutating => RequestEnvelope::mutating_batch(payloads),
        };
        self.submit(api, envelope).await
    }

    fn extract_seqtag(response: &Value) -> Option<String> {
        if let Some(st) = response.get("st").and_then(|v| v.as_str()) {
            return Some(st.to_string());
        }
        if let Some(arr) = response.as_array()
            && let Some(st) = arr.first().and_then(|v| v.as_str())
        {
            return Some(st.to_string());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{RequestClass, RequestEnvelope, RequestRuntime};
    use crate::api::ApiClient;

    #[test]
    fn extract_seqtag_from_object_response() {
        let response = json!({"st": "abc123"});
        assert_eq!(
            RequestRuntime::extract_seqtag(&response),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn extract_seqtag_from_array_response() {
        let response = json!(["abc123", {"ok": 1}]);
        assert_eq!(
            RequestRuntime::extract_seqtag(&response),
            Some("abc123".to_string())
        );
    }

    #[tokio::test]
    async fn empty_batch_is_normalized() {
        let mut runtime = RequestRuntime::new();
        let mut api = ApiClient::new();

        let outcome = runtime
            .submit_batch(&mut api, RequestClass::Mutating, vec![])
            .await
            .expect("empty batch should not fail");

        assert_eq!(outcome.response, Value::Array(vec![]));
        assert_eq!(outcome.seqtag, None);
    }

    #[test]
    fn envelope_builders_assign_expected_class() {
        match RequestEnvelope::read(json!({"a": "uq"})) {
            RequestEnvelope::Single { class, .. } => assert_eq!(class, RequestClass::ReadOnly),
            _ => panic!("expected single request"),
        }

        match RequestEnvelope::mutating_batch(vec![json!({"a": "p"})]) {
            RequestEnvelope::Batch { class, .. } => assert_eq!(class, RequestClass::Mutating),
            _ => panic!("expected batch request"),
        }
    }
}
