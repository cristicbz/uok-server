use failure::{Backtrace, Fail};
use regex::Regex;
use std::result::Result as StdResult;

pub type Result<SuccessT> = StdResult<SuccessT, Error>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(
        display = "Invalid query parameter `{}`, doesn't match `{:?}`.",
        name,
        regex
    )]
    BadQueryParameter {
        name: &'static str,
        regex: &'static Regex,
    },

    #[fail(
        display = "Invalid datetime parameter `{}`, must be ISO8601 / RFC3339.",
        name
    )]
    BadDateParameter { name: &'static str },

    #[fail(display = "Missing required query parameter `{}`.", name)]
    MissingRequiredParameter { name: &'static str },

    #[fail(display = "Missing `Authorization` header. Use `Authorization: Bearer <token>`.")]
    MissingAuthorizationHeader,

    #[fail(display = "Malformed or unknown authorization. Use `Authorization: Bearer <token>`.")]
    MalformedAuthorizationHeader,

    #[fail(display = "Invalid authentication token.")]
    BadAuthenticationToken,

    #[fail(display = "Internal server error.")]
    Internal {
        #[cause]
        error: Box<Fail>,
        backtrace: Option<Backtrace>,
    },
}

impl Error {
    pub fn log_and_get_status_code(&self) -> u16 {
        match self {
            Error::BadQueryParameter { .. }
            | Error::BadDateParameter { .. }
            | Error::MissingRequiredParameter { .. } => {
                info!("Bad request: {}", self);
                400
            }

            Error::MalformedAuthorizationHeader | Error::MissingAuthorizationHeader => {
                info!("Unauthorized: {}", self);
                401
            }
            Error::BadAuthenticationToken => {
                info!("Forbidden: {}", self);
                403
            }

            Error::Internal { error, backtrace } => {
                error!("Internal server error: {}", error);
                let mut cause = &**error;
                while let Some(new_cause) = cause.cause() {
                    error!("    caused by: {}", cause);
                    cause = new_cause;
                }
                error!(
                    "Backtrace:\n{}",
                    backtrace.as_ref().unwrap_or_else(|| cause
                        .cause()
                        .unwrap()
                        .backtrace()
                        .unwrap())
                );
                500
            }
        }
    }
}

pub trait ResultExt {
    type Success;
    type Error;

    fn map_err_internal(self) -> Result<Self::Success>;
}

impl<SuccessT, ErrorT> ResultExt for StdResult<SuccessT, ErrorT>
where
    ErrorT: Fail,
{
    type Success = SuccessT;
    type Error = ErrorT;

    fn map_err_internal(self) -> Result<SuccessT> {
        match self {
            Ok(success) => Ok(success),
            Err(error) => Err(Error::Internal {
                backtrace: if error.backtrace().is_some() {
                    None
                } else {
                    Some(Backtrace::new())
                },
                error: Box::new(error),
            }),
        }
    }
}
