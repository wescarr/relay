use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use actix::Addr;
use axum::body::Bytes;
use axum::extract::Path;
use axum::Router;
use parking_lot::Mutex;
use relay_server::Server;
use relay_system::Controller;
use reqwest::{Client, StatusCode, Url};
use tokio::runtime::Runtime;

use relay_config::Config;

fn random_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn default_config(addr: SocketAddr, upstream: SocketAddr) -> Config {
    let json = serde_json::json!({
        "relay": {
            "upstream": format!("http://{upstream}/"),
            "host": addr.ip().to_string(),
            "port": addr.port(),
            "tls_port": null,
            "tls_private_key": null,
            "tls_cert": null,
        },
        // "sentry": {"dsn": mini_sentry.internal_error_dsn, "enabled": true},
        "limits": {"max_api_file_upload_size": "1MiB"},
        "cache": {"batch_interval": 0},
        "logging": {"level": "trace"},
        "http": {"timeout": 2},
        "processing": {"enabled": false, "kafka_config": [], "redis": ""},
        "outcomes": {
            // Allow fastest possible aggregation:
            "aggregator": {"bucket_interval": 1, "flush_interval": 0},
        },
    });

    Config::from_json_value(json).unwrap()
}

#[derive(Debug, Default)]
struct SentryState {
    captured_envelopes: Vec<Bytes>, // TODO: Import envelope
}

#[derive(Debug)]
struct TestSentry {
    runtime: Runtime,
    addr: SocketAddr,
    state: Arc<Mutex<SentryState>>,
}

impl TestSentry {
    pub fn new() -> Self {
        let runtime = Runtime::new().unwrap();
        let _guard = runtime.enter();

        let state = Arc::new(Mutex::new(SentryState::default()));
        let state_clone = Arc::clone(&state);

        // build our application with a single route
        let app = Router::new().route(
            "/api/:project_id/envelope/",
            axum::routing::post(|Path(project_id): Path<u64>, body: Bytes| async move {
                println!("project ID was: {}", project_id);
                state_clone.lock().captured_envelopes.push(body);
                "{}"
            }),
        );

        // run it with hyper on localhost:3000
        let server =
            axum::Server::bind(&"127.0.0.1:0".parse().unwrap()).serve(app.into_make_service());

        let addr = server.local_addr();
        println!("starting mini-sentry on {}", addr);

        runtime.spawn(server);

        Self {
            runtime,
            addr,
            state,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
}

struct TestRelay {
    addr: SocketAddr,
    controller: Addr<Controller>,
    handle: std::thread::JoinHandle<()>,
}

impl TestRelay {
    // TODO: Overridable config
    pub fn new(upstream: SocketAddr) -> Self {
        let addr = random_addr();

        let (sys, controller) = Controller::create();

        let handle = std::thread::spawn(move || {
            let config = default_config(addr, upstream);
            Server::start(config).unwrap();
            sys.run();
            relay_server::run(config).unwrap();
        });

        Self {
            addr,
            controller,
            handle,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self, path: &str) -> Url {
        let path = path.trim_start_matches('/');
        Url::parse(&format!("http://{}/{}", self.addr(), path)).unwrap()
    }

    pub async fn stop(self) {
        tokio::task::spawn_blocking(move || self.handle.join())
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn test_empty() {
    /* TODOs:
     - init logging in setup mode
     - overridable config
    */

    let sentry = TestSentry::new();
    let relay = TestRelay::new(sentry.addr());

    let client = Client::new();
    let request = client.post(relay.url("/api/42/envelope/")).body("{{}}");
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    relay.stop().await;
}
