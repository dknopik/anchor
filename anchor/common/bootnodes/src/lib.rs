use enr::{CombinedKey, Enr};
use std::fs::read_to_string;
use std::path::PathBuf;

fn get_yaml_for_builtin(network: &str) -> Result<&'static str, String> {
    match network {
        "mainnet" => Ok(include_str!("builtin/mainnet.yaml")),
        "holesky" => Ok(include_str!("builtin/holesky.yaml")),
        _ => Err(format!("No built-in ENRs for {network}")),
    }
}

pub fn get_for_builtin(network: &str) -> Result<Vec<Enr<CombinedKey>>, String> {
    serde_yaml::from_str(get_yaml_for_builtin(network)?).map_err(|e| e.to_string())
}

pub fn get_from_testnet_dir(mut path: PathBuf) -> Result<Vec<Enr<CombinedKey>>, String> {
    path.push("boot_enr_ssv.yaml");
    let yaml =
        read_to_string(&path).map_err(|e| format!("Unable to read boot_enr_ssv.yaml: {e}"))?;
    serde_yaml::from_str(&yaml).map_err(|e| format!("Unable to parse boot_enr_ssv.yaml: {e}"))
}
