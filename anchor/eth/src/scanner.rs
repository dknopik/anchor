use std::sync::Arc;

use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use openssl::{pkey::Public, rsa::Rsa};
use reqwest::Url;
use ssv_network_config::SsvNetworkConfig;
use ssv_types::OperatorId;

use crate::{
    error::ExecutionError,
    event_parser::EventDecoder,
    generated::{SSVContract, SSVContract::Cluster},
    util::get_key_data_from_event_bytes,
};

pub struct Scanner {
    /// Http client connected to the L1 to fetch historical SSV event information
    rpc_client: Arc<RootProvider>,
    /// The network the node is connected to
    network: SsvNetworkConfig,
}

impl Scanner {
    pub fn new(rpc_endpoint: String, network: SsvNetworkConfig) -> Self {
        let http_url: Url = rpc_endpoint.parse().expect("Failed to parse HTTP URL");
        let rpc_client = Arc::new(ProviderBuilder::default().on_http(http_url.clone()));

        Self {
            rpc_client,
            network,
        }
    }

    pub fn provider(&self) -> &Arc<RootProvider> {
        &self.rpc_client
    }

    pub async fn get_nonce(&self, owner: Address) -> Result<u64, ExecutionError> {
        let block = self.rpc_client.get_block_number().await?;
        let logs = self
            .rpc_client
            .get_logs(
                &Filter::new()
                    .address(self.network.ssv_contract)
                    .from_block(0)
                    .to_block(block)
                    .events([SSVContract::ValidatorAdded::SIGNATURE.to_string()])
                    .topic1(owner.into_word()),
            )
            .await?;
        Ok(logs.len() as u64)
    }

    pub async fn get_pubkeys(&self, indices: &[u64]) -> Result<Vec<Rsa<Public>>, ExecutionError> {
        let block = self.rpc_client.get_block_number().await?;
        let logs = self
            .rpc_client
            .get_logs(
                &Filter::new()
                    .address(self.network.ssv_contract)
                    .from_block(0)
                    .to_block(block)
                    .events([SSVContract::OperatorAdded::SIGNATURE.to_string()]),
            )
            .await?;
        let pks = logs
            .into_iter()
            .filter_map(|log| {
                let SSVContract::OperatorAdded {
                    operatorId: operator_id, // The ID of the newly registered operator
                    publicKey,               // The RSA public key
                    ..
                } = SSVContract::OperatorAdded::decode_from_log(&log).ok()?;

                if !indices.contains(&operator_id) {
                    return None;
                }

                let data = get_key_data_from_event_bytes(&publicKey);
                Some(
                    operator_key::public::from_base64(data)
                        .map_err(|err| ExecutionError::Misc(err.to_string())),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        if pks.len() != indices.len() {
            Err(ExecutionError::Misc("not all operators found".to_string()))?;
        }

        Ok(pks)
    }

    pub async fn get_cluster_data(
        &self,
        owner: Address,
        operator_ids: &[OperatorId],
    ) -> Result<Cluster, ExecutionError> {
        let block = self.rpc_client.get_block_number().await?;
        let logs = self
            .rpc_client
            .get_logs(
                &Filter::new()
                    .address(self.network.ssv_contract)
                    .from_block(0)
                    .to_block(block)
                    .events([
                        SSVContract::ValidatorAdded::SIGNATURE.to_string(),
                        SSVContract::ValidatorRemoved::SIGNATURE.to_string(),
                        SSVContract::ClusterLiquidated::SIGNATURE.to_string(),
                        SSVContract::ClusterReactivated::SIGNATURE.to_string(),
                    ])
                    .topic1(owner.into_word()),
            )
            .await?;
        logs.into_iter()
            .rev()
            .filter_map(|l| {
                let (log_operator_ids, cluster) = if let Ok(SSVContract::ValidatorAdded {
                    operatorIds,
                    cluster,
                    ..
                }) =
                    SSVContract::ValidatorAdded::decode_from_log(&l)
                {
                    (operatorIds, cluster)
                } else if let Ok(SSVContract::ValidatorRemoved {
                    operatorIds,
                    cluster,
                    ..
                }) = SSVContract::ValidatorRemoved::decode_from_log(&l)
                {
                    (operatorIds, cluster)
                } else if let Ok(SSVContract::ClusterLiquidated {
                    operatorIds,
                    cluster,
                    ..
                }) = SSVContract::ClusterLiquidated::decode_from_log(&l)
                {
                    (operatorIds, cluster)
                } else if let Ok(SSVContract::ClusterReactivated {
                    operatorIds,
                    cluster,
                    ..
                }) = SSVContract::ClusterReactivated::decode_from_log(&l)
                {
                    (operatorIds, cluster)
                } else {
                    return Some(Err(ExecutionError::InvalidEvent(
                        "recieved invalid log".to_string(),
                    )));
                };
                if operator_ids.len() == log_operator_ids.len()
                    && operator_ids.iter().all(|id| log_operator_ids.contains(id))
                {
                    Some(Ok(cluster))
                } else {
                    None
                }
            })
            .next()
            .unwrap_or(Ok(Cluster {
                validatorCount: 0,
                networkFeeIndex: 0,
                index: 0,
                active: true,
                balance: U256::ZERO,
            }))
    }
}
