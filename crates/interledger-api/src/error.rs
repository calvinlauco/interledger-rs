use chrono::{DateTime, Local};
use http::header::HeaderValue;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{ser::Serializer, Serialize};
use serde_json::error::Category;
use serde_json::{Map, Value};
use std::{
    error::Error as StdError,
    fmt::{self, Display},
};
use warp::{reject::custom, reply::json, reply::Response, Rejection, Reply};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ApiError {
    #[serde(serialize_with = "serialize_type")]
    pub r#type: ApiErrorType,
    pub title: &'static str,
    #[serde(serialize_with = "serialize_status_code")]
    pub status: http::StatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extension_members: Option<Map<String, Value>>,
}

#[derive(Clone, Debug)]
pub(crate) enum ApiErrorType {
    Default,
    Custom(&'static str),
}

fn serialize_status_code<S>(status: &http::StatusCode, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_u16(status.as_u16())
}

fn serialize_type<S>(r#type: &ApiErrorType, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match r#type {
        // https://tools.ietf.org/html/rfc7807#section-4.2
        // about:blank is a pre-defined value
        ApiErrorType::Default => s.serialize_str("about:blank"),
        ApiErrorType::Custom(custom_type) => {
            s.serialize_str(&format!("{}/{}", ERROR_TYPE_PREFIX, custom_type))
        }
    }
}

// top level errors
const ERROR_TYPE_PREFIX: &str = "https://errors.interledger.org/http-api";

impl ApiError {
    #[allow(dead_code)]
    pub fn default_bad_request() -> Self {
        ApiError::bad_request(ApiErrorType::Default, "Bad Request", None, None, None)
    }

    pub fn bad_request(
        r#type: ApiErrorType,
        title: &'static str,
        detail: Option<String>,
        instance: Option<String>,
        extension_members: Option<Map<String, Value>>,
    ) -> Self {
        ApiError {
            r#type,
            title,
            status: http::StatusCode::BAD_REQUEST,
            detail,
            instance,
            extension_members: Some(ApiError::merge_default_extension_members(extension_members)),
        }
    }

    pub fn default_internal_server_error() -> Self {
        ApiError::internal_server_error(
            ApiErrorType::Default,
            "Internal Server Error",
            None,
            None,
            None,
        )
    }

    pub fn internal_server_error(
        r#type: ApiErrorType,
        title: &'static str,
        detail: Option<String>,
        instance: Option<String>,
        extension_members: Option<Map<String, Value>>,
    ) -> Self {
        ApiError {
            r#type,
            title,
            status: http::StatusCode::INTERNAL_SERVER_ERROR,
            detail,
            instance,
            extension_members: Some(ApiError::merge_default_extension_members(extension_members)),
        }
    }

    pub fn default_unauthorized() -> Self {
        ApiError::unauthorized(
            ApiErrorType::Custom("unauthorized"),
            "Unauthorized",
            None,
            None,
            None,
        )
    }

    pub fn unauthorized(
        r#type: ApiErrorType,
        title: &'static str,
        detail: Option<String>,
        instance: Option<String>,
        extension_members: Option<Map<String, Value>>,
    ) -> Self {
        ApiError {
            r#type,
            title,
            status: http::StatusCode::UNAUTHORIZED,
            detail,
            instance,
            extension_members: Some(ApiError::merge_default_extension_members(extension_members)),
        }
    }

    #[allow(dead_code)]
    pub fn default_not_found() -> Self {
        ApiError::not_found(ApiErrorType::Default, "Not Found", None, None, None)
    }

    pub fn not_found(
        r#type: ApiErrorType,
        title: &'static str,
        detail: Option<String>,
        instance: Option<String>,
        extension_members: Option<Map<String, Value>>,
    ) -> Self {
        ApiError {
            r#type,
            title,
            status: http::StatusCode::NOT_FOUND,
            detail,
            instance,
            extension_members: Some(ApiError::merge_default_extension_members(extension_members)),
        }
    }

    fn get_base_extension_members() -> Map<String, Value> {
        let datetime: DateTime<Local> = Local::now();
        let mut map = serde_json::Map::new();
        // TODO What is the best format?
        // TODO Should implement request wide time
        map.insert("datetime".to_owned(), Value::from(datetime.to_rfc3339()));
        map
    }

    fn merge_default_extension_members(
        extension_members: Option<Map<String, Value>>,
    ) -> Map<String, Value> {
        let mut merged_extension_members = ApiError::get_base_extension_members();
        if let Some(map) = extension_members {
            for (k, v) in map {
                merged_extension_members.insert(k, v);
            }
        }
        merged_extension_members
    }
}

impl Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl Reply for ApiError {
    fn into_response(self) -> Response {
        let res = json(&self);
        let mut res = res.into_response();
        *res.status_mut() = self.status;
        res.headers_mut().insert(
            "Content-Type",
            HeaderValue::from_static("application/problem+json"),
        );
        res
    }
}

impl StdError for ApiError {}

impl From<ApiError> for Rejection {
    fn from(from: ApiError) -> Self {
        custom(from)
    }
}

lazy_static! {
    static ref MISSING_FIELD_REGEX: Regex = Regex::new("missing field `(.*)`").unwrap();
}

#[derive(Clone, Debug)]
pub(crate) struct JsonDeserializeError {
    pub(crate) category: Category,
    pub(crate) detail: String,
    pub(crate) path: serde_path_to_error::Path,
}

impl StdError for JsonDeserializeError {}

impl Display for JsonDeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl Reply for JsonDeserializeError {
    fn into_response(self) -> Response {
        let mut extension_member = Map::new();

        // invalid-params should be a plural form even if it is always an array with a single value
        // for the future extendability.

        // if `path` has segments and the first value is not Unknown
        if let Some(segment) = self.path.iter().next() {
            match segment {
                serde_path_to_error::Segment::Unknown => {}
                _ => {
                    let invalid_params = serde_json::json!([ { "name": self.path.to_string() } ]);
                    extension_member.insert("invalid-params".to_string(), invalid_params);
                }
            }
        }

        // if detail contains missing field error
        // it seems that there is no way to handle this cleanly
        if let Some(captures) = MISSING_FIELD_REGEX.captures(&self.detail) {
            if let Some(r#match) = captures.get(1) {
                let invalid_params =
                    serde_json::json!([ { "name": r#match.as_str(), "type": "missing" } ]);
                extension_member.insert("invalid-params".to_string(), invalid_params);
            }
        }

        let r#type = match self.category {
            Category::Syntax => "json-syntax",
            Category::Data => "json-data",
            _ => "Unknown",
        };
        let title = match self.category {
            Category::Syntax => "JSON Syntax Error",
            Category::Data => "JSON Data Error",
            _ => "Unknown JSON Error",
        };

        ApiError::bad_request(
            ApiErrorType::Custom(r#type),
            title,
            Some(self.detail),
            None,
            match extension_member.keys().len() {
                0 => None,
                _ => Some(extension_member),
            },
        )
        .into_response()
    }
}

impl From<JsonDeserializeError> for Rejection {
    fn from(from: JsonDeserializeError) -> Self {
        custom(from)
    }
}
