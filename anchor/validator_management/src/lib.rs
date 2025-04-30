use std::{fs::File, str::FromStr};

use alloy::{
    primitives::{Bytes, U256},
    providers::ProviderBuilder,
    signers::local::{MnemonicBuilder, coins_bip39::English},
};
use clap::Parser;
use eth::generated::{SSVContract, SSVContract::Cluster};
use keysplit::output::OutputData;
use ssv_network_config::SsvNetworkConfig;

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

    #[clap(long, help = "RPC endpoint to access L1 data", value_name = "ENDPOINT")]
    pub rpc: Option<String>,

    #[clap(long, help = "Mainnet, Holesky or Hoodi", value_name = "NETWORK")]
    pub network: String,

    #[clap(help = "Validator share file", value_name = "SHARE_FILE")]
    pub share_file: String,
}

pub fn register_validator(options: Register) -> Result<(), String> {
    let data: OutputData = serde_json::from_reader(
        File::open(options.share_file).map_err(|e| format!("Unable to read file: {e:?}"))?,
    )
    .map_err(|e| format!("Unable to parse file: {e:?}"))?;

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

    let provider = ProviderBuilder::new()
        .wallet(
            MnemonicBuilder::<English>::default()
                .phrase(mnemonic)
                .index(0)
                .map_err(|_| "Invalid mnemonic")?
                .build()
                .map_err(|_| "Invalid mnemonic")?,
        )
        .on_http(rpc);

    let contract = SSVContract::new(network.ssv_contract, &provider);

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| format!("Failed to create a new tokio runtime: {e}"))?;

    for share in data.shares {
        let data = share
            .payload
            .shares_data
            .strip_prefix("0x")
            .unwrap_or(&share.payload.shares_data);
        let data = Bytes::from(hex::decode(data).map_err(|_| "share data is not hex")?);

        let result: Result<_, String> = runtime.block_on(async {
            contract
                .registerValidator(
                    share.payload.public_key.serialize().into(),
                    share.data.operators.iter().map(|o| o.id).collect(),
                    data,
                    U256::from_str("100_000000000000000000").unwrap(), // todo make configurable
                    Cluster {
                        // todo scan blockchain
                        validatorCount: 0,
                        networkFeeIndex: 0,
                        index: 0,
                        active: true,
                        balance: U256::ZERO,
                    },
                )
                .send()
                .await
                .map_err(|e| format!("{e}"))?
                .watch()
                .await
                .map_err(|e| format!("{e}"))
        });
        result?;
    }
    Ok(())
}
