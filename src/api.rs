use chrono::{DateTime, FixedOffset};
use regex::Regex;
use rouille::{Request, Response};
use serde::Serialize;
use std::time::Instant;

use errors::{Error, Result};

pub fn required_param(request: &Request, name: &'static str) -> Result<String> {
    request
        .get_param(name)
        .ok_or_else(|| Error::MissingRequiredParameter { name })
}

pub fn regex_param(regex: &'static Regex, name: &'static str, value: &str) -> Result<()> {
    if regex.is_match(value) {
        Ok(())
    } else {
        Err(Error::BadQueryParameter { name, regex })
    }
}

pub fn required_regex_param(
    request: &Request,
    regex: &'static Regex,
    name: &'static str,
) -> Result<String> {
    let value = required_param(request, name)?;
    regex_param(regex, name, &value)?;
    Ok(value)
}

pub fn date_param(name: &'static str, value: &str) -> Result<DateTime<FixedOffset>> {
    DateTime::parse_from_rfc3339(value).map_err(|_| Error::BadDateParameter { name })
}

pub fn optional_date_param(
    request: &Request,
    name: &'static str,
) -> Result<Option<DateTime<FixedOffset>>> {
    match request.get_param(name) {
        None => Ok(None),
        Some(value) => Ok(Some(date_param(name, &value)?)),
    }
}

pub fn required_date_param(request: &Request, name: &'static str) -> Result<DateTime<FixedOffset>> {
    let value = required_param(request, name)?;
    date_param(name, &value)
}

#[derive(Serialize)]
#[serde(tag = "status")]
enum JsonResponse<SuccessT: Serialize> {
    #[serde(rename = "ok")]
    Ok(SuccessT),

    #[serde(rename = "error")]
    Err { message: String },
}

pub fn success_response<ValueT: Serialize>(status_code: u16, value: ValueT) -> Response {
    assert_eq!(status_code / 100, 2, "{}", status_code);

    let mut response = Response::json(&JsonResponse::Ok(value));
    response.status_code = status_code;
    response
}

pub fn error_response(error: Error) -> Response {
    let mut response = Response::json(&JsonResponse::Err::<()> {
        message: error.to_string(),
    });
    response.status_code = error.log_and_get_status_code();
    response
}

pub struct LoggingWrapper(());
impl LoggingWrapper {
    pub fn new() -> Self {
        LoggingWrapper(())
    }

    pub fn wrap(
        self,
        handler: impl Fn(&Request) -> Result<Response>,
    ) -> impl Fn(&Request) -> Response {
        move |request| {
            let start = Instant::now();
            let response = match handler(request) {
                Ok(response) => response,
                Err(error) => error_response(error),
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
}

pub struct AuthChecker {
    secret: String,
}
impl AuthChecker {
    pub fn new(secret: String) -> Self {
        AuthChecker { secret }
    }

    pub fn check(&self, request: &Request) -> Result<()> {
        let header = request
            .header("Authorization")
            .ok_or(Error::MissingAuthorizationHeader)?;
        let mut split_header = header.trim().split_whitespace();
        let token = match (split_header.next(), split_header.next()) {
            (Some(auth_type), Some(token)) if auth_type == "Bearer" => token,
            _ => return Err(Error::MalformedAuthorizationHeader),
        };

        if token != self.secret {
            return Err(Error::BadAuthenticationToken);
        }

        Ok(())
    }
}
