//! T8n input parsing.
//!
//! Wire format mirrors the geth `evm t8n` contract. The framework
//! (execution-spec-tests) either writes three JSON files (`alloc.json`,
//! `env.json`, `txs.json`) and passes their paths via `--input.*`, or
//! bundles them into a single JSON object on stdin keyed by `alloc`,
//! `env`, `txs`, `blobParams` when the `--input.*` value is `stdin`.

use revm::primitives::{Address, Bytes, B256, U256};
use serde::{de, Deserialize, Deserializer};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use revm::statetest_types::AccountInfo;

/// Deserialize a hex string into a [`B256`], left-padding values
/// shorter than 32 bytes. The execution-spec-tests framework emits
/// `currentRandom` and similar fields as short hex (e.g. `"0x00"`)
/// even though they're semantically 32-byte hashes.
fn deserialize_padded_b256<'de, D>(
    deserializer: D,
) -> Result<Option<B256>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    let Some(s) = s else {
        return Ok(None);
    };
    let stripped = s.strip_prefix("0x").unwrap_or(&s);
    if stripped.len() > 64 {
        return Err(de::Error::custom(format!(
            "hex value too long for B256: {} chars",
            stripped.len()
        )));
    }
    let padded = format!("0x{:0>64}", stripped);
    padded.parse().map(Some).map_err(de::Error::custom)
}

/// Top-level bundle sent over stdin when one or more `--input.*` are
/// routed via `stdin`. Fields are optional so the same struct can soak
/// up partial bundles when some inputs are file-routed.
#[derive(Debug, Default, Deserialize)]
pub struct StdinBundle {
    pub alloc: Option<Alloc>,
    pub env: Option<EnvInput>,
    #[serde(default)]
    pub txs: Option<Vec<TxInput>>,
    #[serde(rename = "blobParams")]
    pub blob_params: Option<BlobParams>,
}

/// Fully resolved t8n inputs after stdin/file routing has been applied.
#[derive(Debug)]
pub struct T8nInput {
    pub alloc: Alloc,
    pub env: EnvInput,
    pub txs: Vec<TxInput>,
    pub blob_params: Option<BlobParams>,
}

/// Pre-state: address → account.
pub type Alloc = BTreeMap<Address, AccountInfo>;

/// Block environment (camelCase JSON, mirrors geth t8n env shape).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvInput {
    pub current_coinbase: Address,
    pub current_gas_limit: U256,
    pub current_number: U256,
    pub current_timestamp: U256,
    #[serde(default, deserialize_with = "deserialize_padded_b256")]
    pub current_random: Option<B256>,
    /// EIP-7843 block slot number (Amsterdam+).
    #[serde(default)]
    pub slot_number: Option<U256>,
    #[serde(default)]
    pub current_difficulty: Option<U256>,
    #[serde(default)]
    pub current_base_fee: Option<U256>,
    #[serde(default)]
    pub current_excess_blob_gas: Option<U256>,
    #[serde(default)]
    pub current_blob_gas_used: Option<U256>,
    #[serde(default)]
    pub parent_hash: Option<B256>,
    #[serde(default)]
    pub parent_difficulty: Option<U256>,
    #[serde(default)]
    pub parent_timestamp: Option<U256>,
    #[serde(default)]
    pub parent_base_fee: Option<U256>,
    #[serde(default)]
    pub parent_gas_used: Option<U256>,
    #[serde(default)]
    pub parent_gas_limit: Option<U256>,
    #[serde(default)]
    pub parent_uncle_hash: Option<B256>,
    #[serde(default)]
    pub parent_blob_gas_used: Option<U256>,
    #[serde(default)]
    pub parent_excess_blob_gas: Option<U256>,
    #[serde(default)]
    pub parent_beacon_block_root: Option<B256>,
    /// Map of block number → block hash for BLOCKHASH lookups. Keys are
    /// hex-encoded U256 (`"0x00"`, `"0x01"`, …); the framework only
    /// includes ancestors the test exercises.
    #[serde(default)]
    pub block_hashes: BTreeMap<U256, B256>,
    #[serde(default)]
    pub ommers: Vec<serde_json::Value>,
    #[serde(default)]
    pub withdrawals: Vec<Withdrawal>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    pub index: U256,
    pub validator_index: U256,
    pub address: Address,
    pub amount: U256,
}

/// Single transaction as supplied by the framework. Fields are optional
/// where a given tx-type doesn't carry them. The framework always
/// includes a recovered `sender` so we can skip signature recovery for
/// happy-path execution.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxInput {
    /// Transaction type (0=Legacy, 1=EIP-2930, 2=EIP-1559, 3=EIP-4844,
    /// 4=EIP-7702). Serialized as a hex U256 (e.g. `"0x0"`).
    #[serde(rename = "type")]
    pub tx_type: U256,
    #[serde(default)]
    pub chain_id: Option<U256>,
    pub nonce: U256,
    pub gas: U256,
    #[serde(default)]
    pub gas_price: Option<U256>,
    #[serde(default)]
    pub max_fee_per_gas: Option<U256>,
    #[serde(default)]
    pub max_priority_fee_per_gas: Option<U256>,
    #[serde(default)]
    pub max_fee_per_blob_gas: Option<U256>,
    #[serde(default)]
    pub to: Option<Address>,
    pub value: U256,
    pub input: Bytes,
    #[serde(default)]
    pub access_list: Vec<AccessListEntry>,
    #[serde(default)]
    pub blob_versioned_hashes: Vec<B256>,
    #[serde(default)]
    pub authorization_list: Vec<Authorization>,
    pub v: U256,
    pub r: U256,
    pub s: U256,
    /// Pre-recovered sender supplied by the framework.
    #[serde(default)]
    pub sender: Option<Address>,
    #[serde(default)]
    pub secret_key: Option<B256>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListEntry {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Authorization {
    pub chain_id: U256,
    pub address: Address,
    pub nonce: U256,
    pub v: U256,
    pub r: U256,
    pub s: U256,
    #[serde(default)]
    pub signer: Option<Address>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BlobParams {
    pub target: U256,
    pub max: U256,
    pub base_fee_update_fraction: U256,
}

/// Resolve a path argument relative to `basedir` unless it's already
/// absolute.
fn resolve(basedir: &Path, source: &str) -> std::path::PathBuf {
    let p = Path::new(source);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        basedir.join(p)
    }
}

/// Load t8n inputs. If any of `alloc_source`/`env_source`/`txs_source`
/// equals `stdin`, stdin is consumed once and parsed as a JSON object
/// keyed by `alloc`/`env`/`txs`/`blobParams`. Other inputs are read from
/// their respective file paths (resolved relative to `basedir`).
pub fn load(
    alloc_source: &str,
    env_source: &str,
    txs_source: &str,
    blob_params_source: Option<&str>,
    basedir: &Path,
) -> Result<T8nInput, String> {
    let need_stdin = alloc_source == "stdin"
        || env_source == "stdin"
        || txs_source == "stdin"
        || blob_params_source == Some("stdin");

    let bundle = if need_stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("read stdin: {e}"))?;
        serde_json::from_str::<StdinBundle>(&buf)
            .map_err(|e| format!("parse stdin bundle: {e}"))?
    } else {
        StdinBundle::default()
    };

    let alloc = match alloc_source {
        "stdin" => bundle
            .alloc
            .ok_or_else(|| "alloc=stdin but bundle has no alloc".to_string())?,
        path => {
            let bytes = std::fs::read(resolve(basedir, path))
                .map_err(|e| format!("read alloc: {e}"))?;
            serde_json::from_slice(&bytes)
                .map_err(|e| format!("parse alloc: {e}"))?
        }
    };

    let env = match env_source {
        "stdin" => bundle
            .env
            .ok_or_else(|| "env=stdin but bundle has no env".to_string())?,
        path => {
            let bytes = std::fs::read(resolve(basedir, path))
                .map_err(|e| format!("read env: {e}"))?;
            serde_json::from_slice(&bytes)
                .map_err(|e| format!("parse env: {e}"))?
        }
    };

    let txs = match txs_source {
        "stdin" => bundle.txs.unwrap_or_default(),
        path => {
            let bytes = std::fs::read(resolve(basedir, path))
                .map_err(|e| format!("read txs: {e}"))?;
            serde_json::from_slice(&bytes)
                .map_err(|e| format!("parse txs: {e}"))?
        }
    };

    let blob_params = match blob_params_source {
        None => bundle.blob_params,
        Some("stdin") => bundle.blob_params,
        Some(path) => {
            let bytes = std::fs::read(resolve(basedir, path))
                .map_err(|e| format!("read blobParams: {e}"))?;
            Some(
                serde_json::from_slice(&bytes)
                    .map_err(|e| format!("parse blobParams: {e}"))?,
            )
        }
    };

    Ok(T8nInput {
        alloc,
        env,
        txs,
        blob_params,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample bundle captured from a real execution-specs fill run
    /// (test_blockhash::block_1 setup block, no txs).
    const SAMPLE_BUNDLE: &str = include_str!("../../../tests/data/t8n_sample_bundle.json");

    #[test]
    fn parses_real_framework_bundle() {
        let bundle: StdinBundle = serde_json::from_str(SAMPLE_BUNDLE)
            .expect("real captured bundle should parse");
        let env = bundle.env.expect("env present");
        assert!(env.parent_beacon_block_root.is_some());
        let alloc = bundle.alloc.expect("alloc present");
        // EIP-2935 history storage contract is pre-deployed.
        let history_addr: Address =
            "0x0000f90827f1c53a10cb7a02335b175320002935"
                .parse()
                .unwrap();
        assert!(alloc.contains_key(&history_addr));
        assert!(bundle.blob_params.is_some());
    }
}
