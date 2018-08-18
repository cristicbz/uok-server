extern crate env_logger;
#[macro_use]
extern crate lazy_static;
extern crate regex;

extern crate rusqlite;

#[macro_use]
extern crate rouille;

#[macro_use]
extern crate structopt;

extern crate chrono;
extern crate failure;

#[macro_use]
extern crate log;

pub mod errors;

use chrono::{DateTime, NaiveDateTime, Utc};
use failure::Error;
use regex::Regex;
use rouille::{Request, Response};
use rusqlite::Connection;
use std::path::PathBuf;
use std::process;
use std::result::Result as StdResult;
use std::sync::Mutex;
use std::time::Instant;
use structopt::StructOpt;

type Result<T> = StdResult<T, Error>;

lazy_static! {
    static ref RX_USERNAME: Regex = Regex::new(r#"^[a-zA-Z0-9._-]{1,256}$"#).expect("bad rx");
    static ref RX_EVENT_TYPE: Regex = Regex::new(r#"^[a-z0-9_]{1,256}$"#).expect("bad rx");
}

/// The backend for the uok mood-tracker app.
#[derive(StructOpt, Debug)]
#[structopt(name = "uok-server")]
struct Args {
    /// Run first-time setup on the database.
    #[structopt(short = "b", long = "bind")]
    bind: String,

    /// Run first-time setup on the database.
    #[structopt(short = "f", long = "first-time-setup")]
    first_time_setup: bool,

    /// Path to sqlite database.
    #[structopt(short = "d", long = "database", parse(from_os_str))]
    database: PathBuf,

    /// Secret token required to authenticate requests.
    #[structopt(short = "s", long = "secret")]
    secret: String,

    /// Secret token required to authenticate requests.
    #[structopt(long = "min-pool-size", default_value = "16")]
    min_pool_size: usize,

    #[structopt(long = "max-pool-size", default_value = "32")]
    max_pool_size: usize,
}

pub trait Handler {
    fn handle(&self, request: &Request) -> Result<Response>;
}
impl<F: Fn(&Request) -> Result<Response>> Handler for F {
    fn handle(&self, request: &Request) -> Result<Response> {
        (self)(request)
    }
}

pub struct Service {
    sqlite: SqlitePool,
}

impl Service {
    fn new(args: &Args) -> Result<Self> {
        let sqlite = SqlitePool::new(
            args.min_pool_size,
            args.max_pool_size,
            args.database.clone(),
        )?;

        Ok(Service { sqlite })
    }

    fn first_time_setup(&self) -> Result<()> {
        self.sqlite.with_connection(|connection| {
            connection.execute(
                "CREATE TABLE Events (
                    username           STRING NOT NULL,
                    time               INTEGER NOT NULL,
                    raw_time           STRING NOT NULL,
                    event_type         STRING NOT NULL,
                    PRIMARY KEY (username, time)
                )",
                &[],
            )?;
            Ok(())
        })
    }

    fn get_events_csv(&self, request: &Request) -> Result<Response> {
        let username = match request.get_param("username") {
            Some(username) => username,
            _ => return Ok(Response::empty_400()),
        };
        let min_time = if let Some(min_time) = request.get_param("min_time") {
            match DateTime::parse_from_rfc3339(&min_time) {
                Ok(datetime) => datetime.timestamp(),
                Err(_) => return Ok(Response::empty_400()),
            }
        } else {
            0
        };
        let max_time = if let Some(max_time) = request.get_param("max_time") {
            match DateTime::parse_from_rfc3339(&max_time) {
                Ok(datetime) => datetime.timestamp(),
                Err(_) => return Ok(Response::empty_400()),
            }
        } else {
            1 << 63
        };

        let mut csv = String::with_capacity(4096);
        self.sqlite.with_connection(|connection| {
            let mut prepared = connection.prepare(
                "SELECT time, raw_time, event_type FROM Events
                 WHERE username = ? AND (time BETWEEN ? AND ?)",
            )?;

            let mut rows = prepared.query(&[&username, &min_time, &max_time])?;
            while let Some(row) = rows.next() {
                let row = row?;
                let time: i64 = row.get(0);
                let raw_time: String = row.get(1);
                let event_type: String = row.get(2);
                let event_type = event_type.replace('"', r#""""#);

                csv.push_str(
                    &DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(time, 0), Utc)
                        .to_rfc3339(),
                );
                csv.push(',');
                csv.push_str(&raw_time);
                csv.push(',');
                csv.push('"');
                csv.push_str(&event_type);
                csv.push('"');
                csv.push('\n');
            }

            Ok(())
        })?;

        Ok(Response::from_data("text/csv", csv))
    }

    fn put_event(&self, request: &Request) -> Result<Response> {
        let username = match request.get_param("username") {
            Some(username) => {
                if RX_USERNAME.is_match(&username) {
                    username
                } else {
                    return Ok(Response::empty_400());
                }
            }
            _ => return Ok(Response::empty_400()),
        };
        let event = match request.get_param("event") {
            Some(event) => {
                if RX_EVENT_TYPE.is_match(&event) {
                    event
                } else {
                    return Ok(Response::empty_400());
                }
            }
            _ => return Ok(Response::empty_400()),
        };
        let (raw_time, time) = match request.get_param("time") {
            Some(raw_time) => match DateTime::parse_from_rfc3339(&raw_time) {
                Ok(time) => (raw_time, time.timestamp()),
                Err(_) => return Ok(Response::empty_400()),
            },
            _ => return Ok(Response::empty_400()),
        };

        self.sqlite.with_connection(|connection| {
            connection.execute(
                "INSERT OR REPLACE INTO Events (username, time, raw_time, event_type)
                 VALUES (?, ?, ?, ?)",
                &[&username, &time, &raw_time, &event],
            )?;
            Ok(())
        })?;
        info!(
            "Added event `{}` for `{}` at {} (raw={}).",
            event, username, time, raw_time
        );
        Ok(Response::empty_204())
    }
}

impl Handler for Service {
    fn handle(&self, request: &Request) -> Result<Response> {
        router!(
            request,
            (GET) (/events) => { self.get_events_csv(request) },
            (PUT) (/events) => { self.put_event(request) },
            _ => { Ok(Response::empty_404()) },
        )
    }
}

struct SqlitePool {
    database: PathBuf,
    pool: Mutex<Vec<Connection>>,
    max_pool_size: usize,
}

impl SqlitePool {
    fn new(min_pool_size: usize, max_pool_size: usize, database: PathBuf) -> Result<Self> {
        assert!(
            max_pool_size >= min_pool_size && min_pool_size > 0,
            "{} {}",
            min_pool_size,
            max_pool_size
        );
        let mut pool = Vec::with_capacity(max_pool_size);
        for _ in 0..min_pool_size {
            pool.push(Connection::open(&database)?);
        }
        Ok(SqlitePool {
            max_pool_size,
            database,
            pool: Mutex::new(pool),
        })
    }

    fn with_connection<T>(&self, with: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let connection = {
            let mut pool = self.pool.lock().expect("posioned mutex");
            if let Some(connection) = pool.pop() {
                connection
            } else {
                Connection::open(&self.database)?
            }
        };
        let output = with(&connection);
        if connection.execute("SELECT 1", &[]).is_ok() {
            let mut pool = self.pool.lock().expect("posioned mutex");
            if pool.len() < self.max_pool_size {
                pool.push(connection);
            }
        }
        output
    }
}

struct LoggingHandler<HandlerT: Handler>(HandlerT);
impl<HandlerT: Handler> LoggingHandler<HandlerT> {
    fn handle(&self, request: &Request) -> Response {
        let start = Instant::now();
        let response = match log_result(self.0.handle(request)) {
            Some(response) => response,
            None => internal_server_error(),
        };
        let time = start.elapsed();
        info!(
            "{:>8} {:40} {:3} {:>3.4}s",
            request.method(),
            request.raw_url(),
            response.status_code,
            time.as_secs() as f64 + f64::from(time.subsec_nanos()) * 1e-9
        );
        response
    }
}

struct AuthChecker<HandlerT: Handler>(String, HandlerT);
impl<HandlerT: Handler> Handler for AuthChecker<HandlerT> {
    fn handle(&self, request: &Request) -> Result<Response> {
        if let Some(header) = request.header("Authorization") {
            let mut split_header = header.trim().split_whitespace();
            if let (Some(auth_type), Some(token)) = (split_header.next(), split_header.next()) {
                if auth_type == "Bearer" && token == self.0 {
                    return self.1.handle(request);
                }
            }
        }
        Ok(unauthorized())
    }
}

fn internal_server_error() -> Response {
    let mut response = Response::from_data(
        "application/json",
        r#"{"status": "error", "description": "internal server error"}"#,
    );
    response.status_code = 500;
    response
}

fn unauthorized() -> Response {
    let mut response = Response::from_data(
        "application/json",
        r#"{"status": "error", "description": "missing or invalid auth token"}"#,
    );
    response.status_code = 401;
    response
}

fn run() -> Result<()> {
    let args = Args::from_args();

    if args.first_time_setup {
        Service::new(&args)?.first_time_setup()?;
    } else {
        let bind_address = args.bind.clone();
        info!("Creating server with options: {:#?}", args);
        let handler = LoggingHandler(AuthChecker(args.secret.clone(), Service::new(&args)?));
        info!("Starting server on {}...", bind_address);
        rouille::start_server(bind_address, move |request| handler.handle(request));
    }

    Ok(())
}

fn log_result<T>(result: Result<T>) -> Option<T> {
    match result {
        Err(error) => {
            let cause = error.as_fail();
            error!("Error: {}", error);
            while let Some(cause) = cause.cause() {
                error!("    caused by: {}", cause);
            }
            error!("Backtrace:\n{}", error.backtrace());
            None
        }
        Ok(value) => Some(value),
    }
}

fn main() {
    process::exit({
        env_logger::Builder::from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
        ).default_format_timestamp(false)
            .init();
        if log_result(run()).is_some() {
            0
        } else {
            1
        }
    });
}
