use eth::scanner::Scanner;
use global_config::GlobalConfig;
use types::SecretKey;

use crate::{KeyShare, KeysplitError, Manual, Onchain, split_keys};

pub struct Split<T> {
    pub key_shares: Vec<T>,
    pub nonce: u64,
}

// Split the key with manually input nonce value and rsa public keys
pub fn manual_split<'a>(
    manual: Manual,
    secret_keys: impl IntoIterator<Item = &'a SecretKey>,
) -> Result<Vec<Split<KeyShare>>, KeysplitError> {
    // Make sure num operators == num keys
    if manual.shared.operators.0.len() != manual.public_keys.len() {
        return Err(KeysplitError::InvalidKeyLen(
            "Number of keys does not match number of operators".to_string(),
        ));
    }

    let mut nonce = manual.nonce;

    secret_keys
        .into_iter()
        .map(|secret_key| {
            // Split the secret key into N keyshares
            let split_keys = split_keys(&manual.shared, secret_key)?;

            // With each keyshare, zip it with its corresponding rsa public key
            let ret = Ok(Split {
                key_shares: split_keys
                    .into_iter()
                    .zip(manual.public_keys.clone())
                    .map(|(split_key, rsa)| KeyShare {
                        id: u64::from(split_key.0),
                        public_key: rsa,
                        keyshare: split_key.1,
                    })
                    .collect(),
                nonce,
            });
            nonce += 1;
            ret
        })
        .collect()
}

// Split the key using onchain data. This takes human error out of the equation and utilizes data
// scrapped from the chain to input the correct operator public keys and owner nonce
pub fn onchain_split<'a>(
    onchain: Onchain,
    global_config: GlobalConfig,
    secret_keys: impl IntoIterator<Item = &'a SecretKey>,
) -> Result<Vec<Split<KeyShare>>, KeysplitError> {
    let rpc = onchain
        .rpc
        .or_else(|| std::env::var("ETH_RPC").ok())
        .ok_or_else(|| KeysplitError::Misc("Specify RPC via --rpc or ETH_RPC env var".into()))?;

    let scanner = Scanner::new(rpc, global_config.ssv_network);

    // Block on the sync, we cannot proceed until this is finished and this prevents refactoring the
    // entire application into async
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| KeysplitError::Misc(format!("Failed to create a new tokio runtime: {e}")))?;
    let (nonce, keys) = runtime.block_on(async {
        (
            scanner.get_nonce(onchain.shared.owner).await,
            scanner.get_pubkeys(&onchain.shared.operators.0).await,
        )
    });

    let public_keys = keys
        .map_err(|e| KeysplitError::InvalidOperator(format!("Failed to fetch operators: {e}")))?;

    let mut nonce =
        nonce.map_err(|e| KeysplitError::Database(format!("Failed to fetch nonce: {e}")))?;

    secret_keys
        .into_iter()
        .map(|secret_key| {
            // Split the secret key into N shares
            let split_keys = split_keys(&onchain.shared, secret_key)?;

            // With each keyshare, zip it with its corresponding rsa public key
            let ret = Ok(Split {
                key_shares: split_keys
                    .into_iter()
                    .zip(public_keys.clone())
                    .map(|(split_key, rsa)| KeyShare {
                        id: u64::from(split_key.0),
                        public_key: rsa,
                        keyshare: split_key.1,
                    })
                    .collect(),
                nonce,
            });
            nonce += 1;
            ret
        })
        .collect()
}
