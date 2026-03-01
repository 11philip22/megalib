use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;
use tracing::debug;

use crate::api::ApiClient;
use crate::error::{MegaError, Result};

const BASE_DELAY: Duration = Duration::from_millis(1_000);
const MAX_DELAY: Duration = Duration::from_millis(60_000);
const IDLE_DELAY: Duration = Duration::from_secs(3_600);

#[derive(Debug, Clone)]
pub(crate) struct ScPollerState {
    pub(crate) scsn: Option<String>,
    pub(crate) wsc_url: Option<String>,
    pub(crate) sc_catchup: bool,
    pub(crate) alerts_catchup_pending: bool,
}

#[derive(Debug)]
pub(crate) enum ScPollerControl {
    UpdateState(ScPollerState),
    Shutdown,
}

#[derive(Debug)]
pub(crate) enum ScPollerEvent {
    ScBatch {
        packets: Vec<Value>,
        seqtags: Vec<String>,
        next_sn: String,
        next_wsc_url: Option<String>,
        ir: bool,
        poll_catchup: bool,
    },
    AlertsBatch {
        alerts: Vec<Value>,
        lsn: Option<String>,
    },
}

pub(crate) struct ScPoller {
    api: ApiClient,
    state: ScPollerState,
    event_tx: mpsc::Sender<ScPollerEvent>,
    control_rx: mpsc::Receiver<ScPollerControl>,
    delay: Duration,
}

impl ScPoller {
    pub(crate) fn new(
        api: ApiClient,
        state: ScPollerState,
        event_tx: mpsc::Sender<ScPollerEvent>,
        control_rx: mpsc::Receiver<ScPollerControl>,
    ) -> Self {
        Self {
            api,
            state,
            event_tx,
            control_rx,
            delay: BASE_DELAY,
        }
    }

    pub(crate) async fn run(mut self) {
        loop {
            let sleep_for = self.next_sleep_duration();
            tokio::select! {
                control = self.control_rx.recv() => {
                    if self.handle_control(control) {
                        break;
                    }
                }
                _ = tokio::time::sleep(sleep_for) => {
                    self.tick().await;
                }
            }
        }
    }

    fn handle_control(&mut self, control: Option<ScPollerControl>) -> bool {
        match control {
            Some(ScPollerControl::UpdateState(state)) => {
                self.state = state;
                self.delay = BASE_DELAY;
                false
            }
            Some(ScPollerControl::Shutdown) | None => true,
        }
    }

    fn next_sleep_duration(&self) -> Duration {
        if self.state.scsn.is_some() {
            self.delay
        } else {
            IDLE_DELAY
        }
    }

    async fn tick(&mut self) {
        if self.state.scsn.is_none() {
            return;
        }

        if let Err(err) = self.poll_sc_until_drained().await {
            let previous_delay = self.delay;
            self.delay = (self.delay * 2).min(MAX_DELAY);
            debug!(
                stage = "sc_long_poll",
                error = %err,
                previous_delay_ms = previous_delay.as_millis() as u64,
                next_delay_ms = self.delay.as_millis() as u64,
                "sc channel request failed; backing off"
            );
            return;
        }

        if self.should_poll_alerts() {
            if let Err(err) = self.poll_user_alerts_once().await {
                let previous_delay = self.delay;
                self.delay = (self.delay * 2).min(MAX_DELAY);
                debug!(
                    stage = "sc50_user_alerts",
                    error = %err,
                    previous_delay_ms = previous_delay.as_millis() as u64,
                    next_delay_ms = self.delay.as_millis() as u64,
                    "sc channel request failed; backing off"
                );
                return;
            }
        }

        if self.delay != BASE_DELAY {
            debug!(
                previous_delay_ms = self.delay.as_millis() as u64,
                next_delay_ms = BASE_DELAY.as_millis() as u64,
                "sc channel recovered; resetting backoff"
            );
        }
        self.delay = BASE_DELAY;
    }

    fn should_poll_alerts(&self) -> bool {
        self.state.scsn.is_some() && !self.state.sc_catchup && self.state.alerts_catchup_pending
    }

    async fn poll_sc_until_drained(&mut self) -> Result<()> {
        loop {
            let Some(sn) = self.state.scsn.as_deref() else {
                return Ok(());
            };

            let poll_catchup = self.state.sc_catchup;
            let (packets, next_sn, next_wsc_url, ir) = self
                .api
                .poll_sc(Some(sn), self.state.wsc_url.as_deref(), poll_catchup)
                .await?;

            let seqtags = extract_seqtags(&packets);
            self.state.scsn = Some(next_sn.clone());
            if let Some(w) = next_wsc_url.clone() {
                self.state.wsc_url = Some(w);
            }
            if !ir && self.state.sc_catchup {
                self.state.sc_catchup = false;
            }

            self.event_tx
                .send(ScPollerEvent::ScBatch {
                    packets,
                    seqtags,
                    next_sn,
                    next_wsc_url,
                    ir,
                    poll_catchup,
                })
                .await
                .map_err(|_| MegaError::Custom("Session actor stopped".to_string()))?;

            if !ir {
                break;
            }
        }

        Ok(())
    }

    async fn poll_user_alerts_once(&mut self) -> Result<()> {
        if self.state.scsn.is_none() {
            return Ok(());
        }

        let (alerts, lsn) = self.api.poll_user_alerts().await?;
        self.state.alerts_catchup_pending = false;
        self.event_tx
            .send(ScPollerEvent::AlertsBatch { alerts, lsn })
            .await
            .map_err(|_| MegaError::Custom("Session actor stopped".to_string()))?;
        Ok(())
    }
}

fn extract_seqtags(packets: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for pkt in packets {
        if let Some(obj) = pkt.as_object() {
            if let Some(st) = obj.get("st").and_then(|v| v.as_str()) {
                out.push(st.to_string());
            }
        }
    }
    out
}
