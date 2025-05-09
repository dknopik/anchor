use alloy::primitives::Keccak256;
use chrono::{DateTime, Utc};
use openssl::{pkey::Public, rsa::Rsa};
use serde::{Deserialize, Serialize};
use types::{Address, PublicKey};

use crate::{
    EncryptedKeyShare, ValidatorKeys,
    cli::SharedKeygenOptions,
    split::Split,
    util::{deserialize_rsa, serialize_rsa},
};

const VERSION: &str = "v1.2.1";

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputData {
    pub version: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    pub shares: Vec<OutputKeyShare>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputKeyShare {
    pub data: OutputKeyData,
    pub payload: Payload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Payload {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKey,
    #[serde(rename = "operatorIds")]
    pub operator_ids: Vec<u64>,
    #[serde(rename = "sharesData")]
    pub shares_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputKeyData {
    #[serde(rename = "ownerNonce")]
    pub owner_nonce: u64,
    #[serde(rename = "ownerAddress")]
    pub owner_address: Address,
    #[serde(rename = "publicKey")]
    pub public_key: PublicKey,
    pub operators: Vec<Operator>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Operator {
    pub id: u64,
    #[serde(
        serialize_with = "serialize_rsa",
        deserialize_with = "deserialize_rsa",
        rename = "operatorKey"
    )]
    pub public_key: Rsa<Public>,
}

impl From<EncryptedKeyShare> for Operator {
    fn from(encrypted: EncryptedKeyShare) -> Self {
        Self {
            id: encrypted.id,
            public_key: encrypted.public_key,
        }
    }
}

impl OutputData {
    pub(crate) fn new(
        encrypted_keys: Vec<Split<EncryptedKeyShare>>,
        shared: &SharedKeygenOptions,
        keys: Vec<ValidatorKeys>,
    ) -> Self {
        let shares = encrypted_keys
            .into_iter()
            .zip(keys)
            .map(|(share, key)| {
                let payload = Payload::new(&share.key_shares, &key, share.nonce, shared.owner);
                let operators: Vec<Operator> =
                    share.key_shares.into_iter().map(Operator::from).collect();

                let output_key_data = OutputKeyData {
                    owner_nonce: share.nonce,
                    owner_address: shared.owner,
                    public_key: key.public_key,
                    operators,
                };

                OutputKeyShare {
                    data: output_key_data,
                    payload,
                }
            })
            .collect();

        Self {
            version: VERSION.to_string(),
            created_at: Utc::now(),
            shares,
        }
    }
}

impl Payload {
    pub(crate) fn new(
        encrypted_keys: &[EncryptedKeyShare],
        keys: &ValidatorKeys,
        nonce: u64,
        owner: Address,
    ) -> Self {
        let signature = Self::create_signature(keys, nonce, owner);
        let (public_keys, encrypted_data) = Self::concatenate_key_data(encrypted_keys);
        let operator_ids: Vec<u64> = encrypted_keys.iter().map(|key| key.id).collect();

        Self {
            public_key: keys.public_key.clone(),
            operator_ids,
            shares_data: format!("0x{signature}{public_keys}{encrypted_data}"),
        }
    }

    // Creates a signature with the owner address and the nonce
    fn create_signature(keys: &ValidatorKeys, nonce: u64, owner: Address) -> String {
        let message = format!("{owner}:{nonce}");
        let mut hasher = Keccak256::new();
        hasher.update(message.as_bytes());

        let signature = keys.secret_key.sign(hasher.finalize());
        hex::encode(signature.serialize())
    }

    // Concatenates together all of the share public keys and the encrypted keyshares for the
    // payload
    fn concatenate_key_data(encrypted_keys: &[EncryptedKeyShare]) -> (String, String) {
        let mut public_keys = String::new();
        let mut encrypted_data = String::new();

        for key in encrypted_keys {
            public_keys.push_str(&hex::encode(key.share_public_key.serialize()));
            encrypted_data.push_str(&hex::encode(&key.encrypted_keyshare));
        }

        (public_keys, encrypted_data)
    }
}
