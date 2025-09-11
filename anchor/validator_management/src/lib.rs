use std::{
    collections::{HashMap, hash_map::Entry},
    fs::File,
    str::FromStr,
};

use alloy::{
    primitives::{Bytes, U256},
    providers::{ProviderBuilder, WalletProvider},
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use clap::Parser;
use eth::{event_parser::EventDecoder, generated::SSVContract, scanner::Scanner};
use keysplit::output::OutputData;
use ssv_network_config::SsvNetworkConfig;
use ssv_types::OperatorId;
use tracing::info;

#[derive(Parser, Clone, Debug)]
#[clap(
    name = "validator",
    about = "Manage your validators in the SSV network"
)]
pub struct ValidatorManagement {
    #[clap(subcommand)]
    pub subcommand: ValidatorManagementSubcommand,
}

#[derive(Parser, Clone, Debug)]
pub enum ValidatorManagementSubcommand {
    Register(Register),
}

// Options for onchain splitting
#[derive(Parser, Clone, Debug)]
#[clap(name = "register", about = "Register a validator on-chain")]
pub struct Register {
    #[clap(long, help = "Mnemonic to use", value_name = "MNEMONIC")]
    pub mnemonic: Option<String>,

    #[clap(
        long,
        help = "Mnemonic index to use",
        default_value = "0",
        value_name = "INDEX"
    )]
    pub mnemonic_index: u32,

    #[clap(long, help = "RPC endpoint to access L1 data", value_name = "ENDPOINT")]
    pub rpc: Option<String>,

    #[clap(long, help = "Mainnet, Holesky or Hoodi", value_name = "NETWORK")]
    pub network: String,

    #[clap(
        long,
        help = "How many tokens to deposit per validator",
        default_value = "1",
        value_name = "SSV"
    )]
    pub ssv_per_validator: u128,

    #[clap(help = "Validator share file", value_name = "SHARE_FILE")]
    pub share_file: String,
}

pub fn register_validator(options: Register) -> Result<(), String> {
    info!("----- Anchor Validator Management -----");
    info!("Reading shares from {}", options.share_file);
    let data: OutputData = serde_json::from_reader(
        File::open(options.share_file).map_err(|e| format!("Unable to read file: {e:?}"))?,
    )
    .map_err(|e| format!("Unable to parse file: {e:?}"))?;
    info!("Successfully read file");

    let mnemonic = options
        .mnemonic
        .or_else(|| std::env::var("MNEMONIC").ok())
        .ok_or("No mnemonic provided")?;
    let rpc = options
        .rpc
        .or_else(|| std::env::var("ETH_RPC").ok())
        .ok_or("No rpc provided")?
        .parse()
        .map_err(|_| "RPC is invalid URL")?;

    let network = SsvNetworkConfig::constant(&options.network)
        .map_err(|_| "Invalid Network")?
        .ok_or("Invalid Network")?;
    let contract = network.ssv_contract;

    let scanner = Scanner::new(rpc, network);

    let provider = ProviderBuilder::new()
        .wallet(
            MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .index(options.mnemonic_index)
                .map_err(|_| "Invalid mnemonic")?
                .build()
                .map_err(|_| "Invalid mnemonic")?,
        )
        .on_provider(scanner.provider());

    let contract = SSVContract::new(contract, &provider);

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create a new tokio runtime: {e}"))?;

    let mut count = 0;
    let chunks = data.shares.chunk_by(|a, b| {
        let split = count == 25 || a.payload.operator_ids != b.payload.operator_ids;
        if split {
            count = 0;
        }
        count += 1;
        !split
    });

    let one_ssv: u128 = 1_000_000_000_000_000_000;

    let mut cluster_states = HashMap::new();

    for chunk in chunks {
        let mut datas = chunk
            .iter()
            .map(|s| {
                let data = s
                    .payload
                    .shares_data
                    .strip_prefix("0x")
                    .unwrap_or(&s.payload.shares_data);
                hex::decode(data)
                    .map_err(|_| "share data is not hex")
                    .map(Bytes::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        info!(
            validators = chunk
                .iter()
                .map(|s| s.payload.public_key.as_hex_string())
                .collect::<Vec<String>>()
                .join(", "),
            "Registering validator(s)...",
        );

        let operator_ids = chunk
            .first()
            .ok_or("empty chunk")?
            .payload
            .operator_ids
            .iter()
            .map(|id| OperatorId(*id))
            .collect::<Vec<_>>();

        let result: Result<_, String> = runtime.block_on(async {
            let cluster = match cluster_states.entry(operator_ids) {
                Entry::Occupied(occupied) => occupied.into_mut(),
                Entry::Vacant(vacant) => {
                    let cluster = scanner
                        .get_cluster_data(
                            provider.wallet().default_signer().address(),
                            vacant.key().as_slice(),
                        )
                        .await
                        .map_err(|e| format!("{e}"))?;
                    vacant.insert(cluster)
                }
            };

            let receipt = if let [share] = chunk {
                contract
                    .registerValidator(
                        share.payload.public_key.serialize().into(),
                        share.data.operators.iter().map(|o| o.id).collect(),
                        datas.pop().ok_or("missing data")?,
                        U256::from(options.ssv_per_validator.checked_mul(one_ssv).unwrap()),
                        cluster.clone(),
                    )
                    .send()
                    .await
            } else {
                contract
                    .bulkRegisterValidator(
                        chunk
                            .iter()
                            .map(|s| s.payload.public_key.serialize().into())
                            .collect(),
                        chunk
                            .first()
                            .map(|s| s.data.operators.iter().map(|o| o.id).collect())
                            .ok_or("empty")?,
                        datas,
                        U256::from(
                            options
                                .ssv_per_validator
                                .checked_mul(one_ssv)
                                .unwrap()
                                .checked_mul(chunk.len() as u128)
                                .unwrap(),
                        ),
                        cluster.clone(),
                    )
                    .send()
                    .await
            }
            .map_err(|e| format!("{e}"))?
            .get_receipt()
            .await
            .map_err(|e| format!("{e}"))?;

            let l = receipt
                .logs()
                .iter()
                .rev()
                .filter_map(|l| SSVContract::ValidatorAdded::decode_from_log(l).ok())
                .next()
                .ok_or("No ValidatorAdded from successful tx")?;
            *cluster = l.cluster;
            Ok(())
        });
        result?;
    }
    info!("Done!");
    Ok(())
}
