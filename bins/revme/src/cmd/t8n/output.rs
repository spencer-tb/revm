//! T8n output emission: writes `result.json`, `alloc.json`, and the
//! RLP-encoded `txs.rlp` body to either stdout or files per the CLI
//! flags.
//!
//! This is intentionally minimal in v1 — state root is computed
//! accurately (the field the framework cares about most for fixture
//! parity), but tx root, receipts root, and the canonical body RLP are
//! placeholders that will be replaced as the conformance work surfaces
//! what the framework strictly validates.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use alloy_consensus::{
    Eip658Value, Receipt, ReceiptEnvelope, ReceiptWithBloom, TxType,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::Bloom;
use alloy_trie::root::ordered_trie_root_encoded;
use revm::{
    database::PlainAccount,
    primitives::{hardfork::SpecId, hex, Address, B256, U256},
};
use serde::Serialize;

/// Keccak256 of the empty RLP list (`0x80`), used as the root hash for
/// any empty trie. Matches `EMPTY_ROOT_HASH` from alloy-trie.
const EMPTY_ROOT_HASH_HEX: &str =
    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

/// Keccak256 of the empty byte slice. Used as the requests hash when no
/// requests are emitted.
const EMPTY_REQUESTS_HASH_HEX: &str =
    "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

use crate::cmd::statetest::merkle_trie::{log_rlp_hash, state_merkle_trie_root};

use super::execute::{ExecuteOutput, TxReceipt};

/// Top-level result JSON, modelled to match the fields execution-specs'
/// `Result` Pydantic model reads back (`cli_types.py`).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResultJson {
    state_root: String,
    tx_root: String,
    receipts_root: String,
    logs_hash: String,
    logs_bloom: String,
    receipts: Vec<ReceiptJson>,
    rejected: Vec<RejectedJson>,
    current_difficulty: String,
    gas_used: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_base_fee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_excess_blob_gas: Option<String>,
    blob_gas_used: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    withdrawals_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requests_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requests: Option<Vec<String>>,
    /// EIP-7928 Block-level Access List hash. Amsterdam+ only; the
    /// framework requires this even for blocks with no BAL entries.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_access_list_hash: Option<String>,
    /// EIP-7928 Block-level Access List bytes (RLP-encoded). Amsterdam+.
    /// For an empty BAL this is the empty-list RLP `0x80`.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_access_list: Option<String>,
    /// Block-level exception emitted by the t8n. The framework's
    /// exception mapper matches the string against its registered
    /// regexes / substrings to attribute the exception. Used for
    /// failed post-block system calls (EIP-7002, EIP-7251) and other
    /// block-level invalidity scenarios.
    #[serde(skip_serializing_if = "Option::is_none")]
    block_exception: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptJson {
    #[serde(rename = "type")]
    tx_type: String,
    status: String,
    cumulative_gas_used: String,
    gas_used: String,
    logs_bloom: String,
    logs: Vec<LogJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contract_address: Option<String>,
    transaction_hash: String,
    transaction_index: String,
    block_hash: String,
    block_number: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LogJson {
    address: String,
    topics: Vec<String>,
    data: String,
    block_number: String,
    transaction_hash: String,
    transaction_index: String,
    block_hash: String,
    log_index: String,
    removed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RejectedJson {
    index: usize,
    error: String,
}

/// Account entry in alloc JSON output (same shape as input alloc).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountJson {
    balance: String,
    nonce: String,
    code: String,
    storage: BTreeMap<String, String>,
}

/// Resolve a CLI output target. `stdout` writes to stdout; anything
/// else is treated as a path relative to `basedir`.
enum OutputTarget {
    Stdout,
    File(PathBuf),
}

impl OutputTarget {
    fn resolve(value: &str, basedir: &Path) -> Self {
        if value == "stdout" {
            Self::Stdout
        } else {
            let p = Path::new(value);
            let resolved = if p.is_absolute() {
                p.to_path_buf()
            } else {
                basedir.join(p)
            };
            Self::File(resolved)
        }
    }

    fn write(&self, contents: &[u8]) -> Result<(), String> {
        match self {
            Self::Stdout => {
                use std::io::Write;
                std::io::stdout()
                    .write_all(contents)
                    .map_err(|e| format!("write stdout: {e}"))
            }
            Self::File(path) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
                }
                std::fs::write(path, contents)
                    .map_err(|e| format!("write {}: {e}", path.display()))
            }
        }
    }
}

/// Compute the EIP-4895 withdrawals trie root from the supplied
/// withdrawals list. Empty list → EMPTY_ROOT_HASH.
pub fn compute_withdrawals_root(
    withdrawals: &[super::input::Withdrawal],
) -> B256 {
    use alloy_eips::eip4895::Withdrawal as AlloyWithdrawal;
    if withdrawals.is_empty() {
        return alloy_trie::EMPTY_ROOT_HASH;
    }
    let alloy_list: Vec<AlloyWithdrawal> = withdrawals
        .iter()
        .map(|w| AlloyWithdrawal {
            index: w.index.try_into().unwrap_or_default(),
            validator_index: w.validator_index.try_into().unwrap_or_default(),
            address: w.address,
            amount: w.amount.try_into().unwrap_or_default(),
        })
        .collect();
    alloy_trie::root::ordered_trie_root(&alloy_list)
}

/// EIP-7685 `requests_hash`: `sha256(sha256(req_0) || sha256(req_1) || …)`.
/// Items whose only byte is the request-type prefix (i.e. empty
/// payload) are skipped, per geth's `CalcRequestsHash`. Mirror of
/// `core/types/block.go::CalcRequestsHash`.
fn calc_requests_hash(requests: &[Vec<u8>]) -> B256 {
    use sha2::{Digest, Sha256};
    let mut accumulator = Sha256::new();
    for item in requests {
        if item.len() > 1 {
            let inner = Sha256::digest(item);
            accumulator.update(inner);
        }
    }
    B256::from_slice(&accumulator.finalize())
}

/// Emit t8n outputs from the execute result.
pub fn emit(
    output: &ExecuteOutput,
    result_target: &str,
    alloc_target: &str,
    body_target: &str,
    basedir: &Path,
    withdrawals: &[super::input::Withdrawal],
) -> Result<(), String> {
    // ---- state root + logs hash via existing helpers ----
    let accounts: Vec<(Address, &PlainAccount)> =
        output.state.cache.trie_account().into_iter().collect();
    let state_root = state_merkle_trie_root(accounts.iter().copied());

    let all_logs: Vec<_> =
        output.receipts.iter().flat_map(|r| r.logs.clone()).collect();
    let logs_hash = log_rlp_hash(&all_logs);

    // ---- block-level logs bloom ----
    let mut bloom = Bloom::default();
    bloom.accrue_logs(&all_logs);

    // ---- receipts root (EIP-2718 typed-envelope trie) ----
    let receipt_envelopes: Vec<Vec<u8>> = output
        .receipts
        .iter()
        .map(|r| {
            let alloy_receipt = Receipt {
                status: Eip658Value::Eip658(r.status),
                cumulative_gas_used: r.cumulative_gas_used,
                logs: r.logs.clone(),
            };
            let with_bloom = ReceiptWithBloom {
                logs_bloom: {
                    let mut b = Bloom::default();
                    b.accrue_logs(&alloy_receipt.logs);
                    b
                },
                receipt: alloy_receipt,
            };
            let tx_type =
                tx_type_from_u8(r.tx_type).unwrap_or(TxType::Legacy);
            let envelope = ReceiptEnvelope::<revm::primitives::Log>::from_typed(
                tx_type, with_bloom,
            );
            envelope.encoded_2718()
        })
        .collect();
    let receipts_root = if receipt_envelopes.is_empty() {
        EMPTY_ROOT_HASH_HEX.to_string()
    } else {
        let root = ordered_trie_root_encoded(&receipt_envelopes);
        hex_b256(&root)
    };

    // ---- per-receipt JSON ----
    let block_number_hex = format!("0x{:x}", output.block_env.number);
    let receipts_json: Vec<ReceiptJson> = output
        .receipts
        .iter()
        .enumerate()
        .map(|(idx, r)| build_receipt_json(idx, r, &block_number_hex))
        .collect();

    let rejected_json: Vec<RejectedJson> = output
        .rejected
        .iter()
        .map(|r| RejectedJson {
            index: r.index,
            error: r.error.clone(),
        })
        .collect();

    // tx root / receipts root: placeholders for v1 (empty trie).
    // Fork-conditional fields: withdrawals_root for Shanghai+,
    // requests_hash for Prague+.
    let withdrawals_root = if output.spec_id.is_enabled_in(SpecId::SHANGHAI) {
        Some(hex_b256(&compute_withdrawals_root(withdrawals)))
    } else {
        None
    };
    let (requests_hash, requests) = if output.spec_id.is_enabled_in(SpecId::PRAGUE)
    {
        let reqs: &[Vec<u8>] = output
            .requests
            .as_deref()
            .unwrap_or(&[]);
        let hash = if reqs.is_empty() {
            // No payloads at all: emit the empty-list hash (sha256 of
            // empty input).
            EMPTY_REQUESTS_HASH_HEX.to_string()
        } else {
            hex_b256(&calc_requests_hash(reqs))
        };
        let serialized: Vec<String> = reqs
            .iter()
            .map(|r| format!("0x{}", hex::encode(r)))
            .collect();
        (Some(hash), Some(serialized))
    } else {
        (None, None)
    };

    // EIP-7928 BAL (Amsterdam+): the real RLP-encoded BAL and its
    // keccak256, both computed in execute.rs from revm's accumulated
    // (and canonically sorted) access list.
    let (block_access_list_hash, block_access_list) = match (
        &output.block_access_list,
        &output.block_access_list_hash,
    ) {
        (Some(rlp), Some(hash)) => (
            Some(hex_b256(hash)),
            Some(format!("0x{}", hex::encode(rlp))),
        ),
        _ => (None, None),
    };

    let result = ResultJson {
        state_root: hex_b256(&state_root),
        tx_root: EMPTY_ROOT_HASH_HEX.to_string(),
        receipts_root,
        logs_hash: hex_b256(&logs_hash),
        logs_bloom: format!("0x{}", hex::encode(bloom.0)),
        receipts: receipts_json,
        rejected: rejected_json,
        current_difficulty: format!("0x{:x}", output.block_env.difficulty),
        gas_used: format!("0x{:x}", output.gas_used),
        current_base_fee: Some(format!("0x{:x}", output.base_fee)),
        current_excess_blob_gas: output
            .excess_blob_gas
            .map(|e| format!("0x{:x}", e)),
        blob_gas_used: format!("0x{:x}", output.blob_gas_used),
        withdrawals_root,
        requests_hash,
        requests,
        block_access_list_hash,
        block_access_list,
        block_exception: output.block_exception.clone(),
    };

    let result_bytes = serde_json::to_vec_pretty(&result)
        .map_err(|e| format!("serialize result: {e}"))?;
    OutputTarget::resolve(result_target, basedir).write(&result_bytes)?;

    // ---- alloc JSON ----
    let alloc_map: BTreeMap<String, AccountJson> = accounts
        .iter()
        .map(|(addr, account)| {
            let code_hex: String = match account.info.code.as_ref() {
                Some(c) => {
                    format!("0x{}", hex::encode(c.original_byte_slice()))
                }
                None => "0x".to_string(),
            };
            let storage: BTreeMap<String, String> = account
                .storage
                .iter()
                .filter(|(_k, v)| !v.is_zero())
                .map(|(k, v): (&U256, &U256)| {
                    (format!("0x{:x}", k), format!("0x{:x}", v))
                })
                .collect();
            let json = AccountJson {
                balance: format!("0x{:x}", account.info.balance),
                nonce: format!("0x{:x}", account.info.nonce),
                code: code_hex,
                storage,
            };
            (format!("0x{}", hex::encode(addr.0)), json)
        })
        .collect();
    let alloc_bytes = serde_json::to_vec_pretty(&alloc_map)
        .map_err(|e| format!("serialize alloc: {e}"))?;
    OutputTarget::resolve(alloc_target, basedir).write(&alloc_bytes)?;

    // ---- body RLP (placeholder: empty list) ----
    // Real implementation will encode the typed-tx envelopes as
    // rlp([typed_tx_bytes, ...]). For v1 we emit an empty list which
    // is `0xc0` so downstream consumers at least get well-formed RLP.
    let body_bytes = [0xc0u8];
    OutputTarget::resolve(body_target, basedir).write(&body_bytes)?;

    Ok(())
}

fn build_receipt_json(
    idx: usize,
    r: &TxReceipt,
    block_number_hex: &str,
) -> ReceiptJson {
    let mut bloom = Bloom::default();
    bloom.accrue_logs(&r.logs);
    let bloom_hex = format!("0x{}", hex::encode(bloom.0));
    let placeholder_hash =
        "0x0000000000000000000000000000000000000000000000000000000000000000"
            .to_string();

    let logs = r
        .logs
        .iter()
        .enumerate()
        .map(|(log_idx, log)| LogJson {
            address: format!("0x{}", hex::encode(log.address.0)),
            topics: log
                .topics()
                .iter()
                .map(|t| format!("0x{}", hex::encode(t.0)))
                .collect(),
            data: format!("0x{}", hex::encode(&log.data.data)),
            block_number: block_number_hex.to_string(),
            transaction_hash: placeholder_hash.clone(),
            transaction_index: format!("0x{:x}", idx),
            block_hash: placeholder_hash.clone(),
            log_index: format!("0x{:x}", log_idx),
            removed: false,
        })
        .collect();

    ReceiptJson {
        tx_type: format!("0x{:x}", r.tx_type),
        status: format!("0x{}", if r.status { "1" } else { "0" }),
        cumulative_gas_used: format!("0x{:x}", r.cumulative_gas_used),
        gas_used: format!("0x{:x}", r.gas_used),
        logs_bloom: bloom_hex,
        logs,
        contract_address: r
            .contract_address
            .map(|a| format!("0x{}", hex::encode(a.0))),
        transaction_hash: placeholder_hash.clone(),
        transaction_index: format!("0x{:x}", idx),
        block_hash: placeholder_hash,
        block_number: block_number_hex.to_string(),
    }
}

fn hex_b256(h: &B256) -> String {
    format!("0x{}", hex::encode(h.0))
}

fn tx_type_from_u8(t: u8) -> Option<TxType> {
    Some(match t {
        0 => TxType::Legacy,
        1 => TxType::Eip2930,
        2 => TxType::Eip1559,
        3 => TxType::Eip4844,
        4 => TxType::Eip7702,
        _ => return None,
    })
}

// Suppress unused warning for U256 (we may use it for richer hex
// formatting later).
#[allow(dead_code)]
fn hex_u256(v: &U256) -> String {
    format!("0x{:x}", v)
}
