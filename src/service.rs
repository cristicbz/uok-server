use regex::Regex;
use rouille::{Request, Response};

use super::api;
use super::errors::Result;
use super::store::{Event, EventStore};

lazy_static! {
    static ref RX_USERNAME: Regex = Regex::new(r#"^[a-zA-Z0-9._-]{1,256}$"#).expect("bad rx");
    static ref RX_EVENT_TYPE: Regex = Regex::new(r#"^[a-z0-9_]{1,256}$"#).expect("bad rx");
}

pub struct Service {
    store: EventStore,
}

impl Service {
    pub fn new(store: EventStore) -> Self {
        Service { store }
    }

    pub fn handle(&self, request: &Request) -> Result<Response> {
        router!(
            request,
            (GET) (/events) => { self.get_events_csv(request) },
            (PUT) (/events) => { self.put_event(request) },
            _ => { Ok(Response::empty_404()) },
        )
    }

    pub fn get_events_csv(&self, request: &Request) -> Result<Response> {
        Ok(Response::from_data(
            "text/csv",
            self.store.get_csv(
                &api::required_regex_param(request, &RX_USERNAME, "username")?,
                api::optional_date_param(request, "min_time")?,
                api::optional_date_param(request, "max_time")?,
            )?,
        ))
    }

    pub fn put_event(&self, request: &Request) -> Result<Response> {
        let raw_time = api::required_date_param(request, "time")?;
        let event = Event {
            raw_time,
            username: api::required_regex_param(request, &RX_USERNAME, "username")?,
            event_type: api::required_regex_param(request, &RX_EVENT_TYPE, "event")?,
            time: raw_time.timestamp(),
        };

        self.store.put(&event)?;
        info!("Added event {:?}.", event);
        Ok(api::success_response(201, EventResponse { event }))
    }
}

#[derive(Serialize)]
struct EventResponse {
    event: Event,
}
