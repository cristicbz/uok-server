extern crate chrono;
extern crate env_logger;
extern crate r2d2;
extern crate r2d2_sqlite;
extern crate regex;
extern crate serde;

#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate rouille;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate structopt;

mod api;
mod errors;
mod service;
mod store;

use failure::Error;
use r2d2_sqlite::SqliteConnectionManager;
use rouille::{Request, Response};
use std::path::PathBuf;
use std::process;
use structopt::StructOpt;

use self::api::{AuthChecker, LoggingWrapper};
use self::service::Service;
use self::store::{EventStore, SqlitePool};

/// The backend for the uok mood-tracker app.
#[derive(StructOpt, Debug)]
#[structopt(name = "uok-server")]
struct Args {
    /// Run first-time setup on the database.
    #[structopt(short = "b", long = "bind")]
    bind: String,

    /// Path to sqlite database.
    #[structopt(short = "d", long = "database", parse(from_os_str))]
    database: PathBuf,

    /// Secret token required to authenticate requests.
    #[structopt(short = "s", long = "secret")]
    secret: String,
}

fn make_server(args: Args) -> Result<impl Fn(&Request) -> Response, Error> {
    let store = EventStore::new(SqlitePool::new(SqliteConnectionManager::file(
        args.database,
    ))?)?;
    let logging = LoggingWrapper::new();
    let auth = AuthChecker::new(args.secret);
    let service = Service::new(store);
    Ok(logging.wrap(move |request| {
        auth.check(request)?;
        service.handle(request)
    }))
}

fn run() -> Result<(), Error> {
    let args = Args::from_args();
    info!("Creating server with options: {:#?}", args);
    let bind = args.bind.clone();
    let server = make_server(args)?;
    info!("Starting server on {}...", bind);
    rouille::start_server(bind, server);
}

fn init_logging() {
    use env_logger::{Builder, Env, DEFAULT_FILTER_ENV};
    Builder::from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "info"))
        .default_format_timestamp(false)
        .init();
}

fn main() {
    init_logging();
    if let Err(error) = run() {
        error!("Fatal error: {}", error);
        let mut cause = error.as_fail();
        while let Some(new_cause) = cause.cause() {
            cause = new_cause;
            error!("    caused by: {}", cause);
        }
        error!("Backtrace:\n{}", error.backtrace());
        process::exit(1);
    }
}
