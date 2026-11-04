use super::{CONSENT_TIMEOUT, Command, Phase, Policy, queue::Queue};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use synra_protocol::ids::SessionId;
use synra_protocol::{DeviceId, PluginId};

mod transport;

/// Controller state returned only to its owning plugin.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientSnapshot {
    /// Local opaque handle, bound to the caller plugin.
    pub session: SessionId,
    /// Selected peer; never automatically replaced by another device.
    pub target: DeviceId,
    /// Pending, active or ended.
    pub phase: Phase,
    /// Last terminal reason.
    pub reason: Option<String>,
    /// Last sequence the computer actually acknowledged after applying input.
    pub acknowledged: u64,
    /// Median host-queue-to-execution-ack milliseconds on this controller's monotonic clock.
    pub p50_ms: u64,
    /// 95th percentile of the most recent 120 acknowledged samples.
    pub p95_ms: u64,
    /// 99th percentile of the most recent 120 acknowledged samples.
    pub p99_ms: u64,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "camelCase", deny_unknown_fields)]
enum Request {
    Open {
        target: DeviceId,
    },
    Frame {
        session: SessionId,
        commands: Vec<Command>,
    },
    Status {
        session: SessionId,
    },
    Close {
        session: SessionId,
    },
}

struct Client {
    plugin: PluginId,
    generation: i64,
    state: Mutex<ClientSnapshot>,
    closed: AtomicBool,
    ui_seen: Mutex<Instant>,
    queue: Queue,
    samples: Mutex<VecDeque<u64>>,
}

impl Client {
    fn end(&self, reason: &str) {
        self.closed.store(true, Ordering::Release);
        let mut state = self.state.lock();
        state.phase = Phase::Ended;
        if state.reason.is_none() {
            state.reason = Some(reason.to_owned());
        }
    }

    fn active(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self.ui_seen.lock().elapsed() < Duration::from_millis(750)
    }

    fn acknowledge(&self, sequence: u64, sampled: Instant, measured: bool) {
        if !measured {
            self.state.lock().acknowledged = sequence;
            return;
        }
        let values = {
            let mut samples = self.samples.lock();
            samples.push_back(u64::try_from(sampled.elapsed().as_millis()).unwrap_or(u64::MAX));
            if samples.len() > 120 {
                samples.pop_front();
            }
            let mut values: Vec<_> = samples.iter().copied().collect();
            drop(samples);
            values.sort_unstable();
            values
        };
        let percentile = |percent: usize| {
            values
                .get((values.len().saturating_sub(1) * percent) / 100)
                .copied()
                .unwrap_or(0)
        };
        let mut state = self.state.lock();
        state.acknowledged = sequence;
        state.p50_ms = percentile(50);
        state.p95_ms = percentile(95);
        state.p99_ms = percentile(99);
    }
}

/// One bounded real-time connection per plugin. Network IO belongs to its worker, never the Wasm call.
pub struct Controller {
    policy: Arc<dyn Policy>,
    clients: Mutex<HashMap<PluginId, Arc<Client>>>,
    stopping: AtomicBool,
}

impl Controller {
    /// Attach the same durable policy and peer transport the receiving service uses.
    pub fn new(policy: Arc<dyn Policy>) -> Self {
        Self {
            policy,
            clients: Mutex::new(HashMap::new()),
            stopping: AtomicBool::new(false),
        }
    }

    /// Process a headless-only host call; status and frames renew the visible controller's short lease.
    /// # Errors
    /// Refuses malformed arguments, another plugin's handle, revoked grants and full queues.
    pub fn request(&self, plugin: &PluginId, json: &str) -> Result<String, String> {
        if self.stopping.load(Ordering::Acquire) {
            return Err("host stopped".to_owned());
        }
        if json.len() > 16_384 {
            return Err("input request too large".to_owned());
        }
        let request: Request = serde_json::from_str(json).map_err(|error| error.to_string())?;
        let client = match request {
            Request::Open { target } => self.open(plugin, target)?,
            Request::Frame { session, commands } => {
                let client = self.owned(plugin, session)?;
                if client.state.lock().phase != Phase::Active {
                    return Err("input session is not active".to_owned());
                }
                *client.ui_seen.lock() = Instant::now();
                if let Err(reason) = client.queue.push(commands) {
                    client.end(&reason);
                    return Err(reason);
                }
                client
            }
            Request::Status { session } => {
                let client = self.owned(plugin, session)?;
                *client.ui_seen.lock() = Instant::now();
                client
            }
            Request::Close { session } => {
                let client = self.owned(plugin, session)?;
                client.end("closed");
                client
            }
        };
        let snapshot = client.state.lock().clone();
        serde_json::to_string(&snapshot).map_err(|error| error.to_string())
    }

    /// End a controller when its page closes or its plugin stops.
    pub fn close_plugin(&self, plugin: &PluginId) {
        let client = self.clients.lock().get(plugin).cloned();
        if let Some(client) = client {
            client.end("page closed");
        }
    }

    /// Refuse new controllers and end every current source before a deliberate host exit.
    pub fn shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
        let clients: Vec<_> = self.clients.lock().values().cloned().collect();
        for client in clients {
            client.end("host stopped");
        }
    }

    fn owned(&self, plugin: &PluginId, session: SessionId) -> Result<Arc<Client>, String> {
        self.clients
            .lock()
            .get(plugin)
            .filter(|client| client.state.lock().session == session)
            .cloned()
            .ok_or_else(|| "this plugin owns no such input session".to_owned())
    }

    fn open(&self, plugin: &PluginId, target: DeviceId) -> Result<Arc<Client>, String> {
        let generation = self.policy.authorize(target, plugin, false)?;
        self.close_plugin(plugin);
        let client = Arc::new(Client {
            plugin: plugin.clone(),
            generation,
            closed: AtomicBool::new(false),
            ui_seen: Mutex::new(Instant::now()),
            queue: Queue::default(),
            samples: Mutex::new(VecDeque::new()),
            state: Mutex::new(ClientSnapshot {
                session: SessionId::new(),
                target,
                phase: Phase::Pending,
                reason: None,
                acknowledged: 0,
                p50_ms: 0,
                p95_ms: 0,
                p99_ms: 0,
            }),
        });
        let mut clients = self.clients.lock();
        if self.stopping.load(Ordering::Acquire) {
            return Err("host stopped".to_owned());
        }
        clients.insert(plugin.clone(), Arc::clone(&client));
        drop(clients);
        let worker = Arc::clone(&client);
        let policy = Arc::clone(&self.policy);
        std::thread::Builder::new()
            .name("synra-input-controller".to_owned())
            .spawn(move || {
                let result = transport::run(&worker, policy.as_ref());
                worker.end(result.as_ref().err().map_or("closed", String::as_str));
            })
            .map_err(|error| {
                client.end("worker could not start");
                error.to_string()
            })?;
        Ok(client)
    }
}
