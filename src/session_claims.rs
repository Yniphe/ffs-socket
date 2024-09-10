use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) struct SessionClaims {
    #[serde(with = "jwt_numeric_date")]
    pub(crate) iat: OffsetDateTime,
    #[serde(with = "jwt_numeric_date")]
    pub(crate) exp: OffsetDateTime,

    pub(crate) identifier: u32,
    pub(crate) username: String
}

impl SessionClaims {
    #[allow(dead_code)]
    pub fn new(identifier: u32, username: &str) -> Self {
        let iat = OffsetDateTime::now_utc();
        let exp = iat + Duration::days(365);

        let iat = iat
            .date()
            .with_hms_milli(iat.hour(), iat.minute(), iat.second(), 0)
            .unwrap()
            .assume_utc();

        let exp = exp
            .date()
            .with_hms_milli(exp.hour(), exp.minute(), exp.second(), 0)
            .unwrap()
            .assume_utc();

        Self {
            identifier,
            username: String::from(username),
            exp,
            iat
        }
    }
}

mod jwt_numeric_date {
    //! Custom serialization of OffsetDateTime to conform with the JWT spec (RFC 7519 section 2, "Numeric Date")
    use serde::{self, Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    /// Serializes an OffsetDateTime to a Unix timestamp (milliseconds since 1970/1/1T00:00:00T)
    pub fn serialize<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = date.unix_timestamp();
        serializer.serialize_i64(timestamp)
    }

    /// Attempts to deserialize an i64 and use as a Unix timestamp
    pub fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        OffsetDateTime::from_unix_timestamp(i64::deserialize(deserializer)?)
            .map_err(|_| serde::de::Error::custom("invalid Unix timestamp value"))
    }
}