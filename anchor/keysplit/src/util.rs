use std::str::FromStr;

use hex::FromHex;
use openssl::{pkey::Public, rsa::Rsa};
use serde::{Deserialize, Deserializer, Serializer};
use types::Address;

// Serde deserialization and serialization helper functions
pub(crate) fn hex_to_buffer<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}

pub(crate) fn parse_address(s: &str) -> Result<Address, String> {
    Address::from_str(s).map_err(|e| e.to_string())
}

pub(crate) fn serialize_rsa<S>(key: &Rsa<Public>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let encoded = operator_key::public::to_base64(key).map_err(serde::ser::Error::custom)?;
    s.serialize_str(&encoded)
}

pub(crate) fn deserialize_rsa<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Rsa<Public>, D::Error> {
    let data = String::deserialize(deserializer)?;
    let key =
        operator_key::public::from_base64(data.as_bytes()).map_err(serde::de::Error::custom)?;
    Ok(key)
}
