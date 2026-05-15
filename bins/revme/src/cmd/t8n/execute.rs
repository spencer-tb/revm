//! T8n block execution: takes parsed input, runs the pre-block hooks,
//! per-tx execution loop, post-block hooks, and returns the post-state
//! plus accumulated receipts.

use alloy_eips::eip1559::{calc_next_block_base_fee, BaseFeeParams};
use revm::{
    bytecode::Bytecode,
    context::{cfg::CfgEnv, BlockEnv, ContextTr, TxEnv},
    context_interface::{
        block::BlobExcessGasAndPrice,
        result::{ExecutionResult, Output},
    },
    database::{EmptyDB, State},
    handler::EvmTr,
    primitives::{
        eip4844::{
            BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN,
            BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
        },
        hardfork::SpecId,
        keccak256, Address, Bytes, Log, TxKind, B256, U256,
    },
    state::AccountInfo as EvmAccountInfo,
    statetest_types::blockchain::Withdrawal as TxWithdrawal,
    Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext,
};

use super::fork::fork_to_spec_id;
use super::input::{EnvInput, T8nInput, TxInput};
use crate::cmd::blockchaintest::{
    post_block::post_block_transition,
    pre_block::pre_block_transition,
};

/// EIP-7928 per-item gas charge used to bound the block access list
/// size (EELS amsterdam `GasCosts.BLOCK_ACCESS_LIST_ITEM`).
const BLOCK_ACCESS_LIST_ITEM_GAS: u64 = 2000;

/// Result of running one t8n block.
pub struct ExecuteOutput {
    /// Final state after block execution. Owned so callers can extract
    /// post-state for serialisation.
    pub state: State<EmptyDB>,
    /// Per-tx receipts in the same order as accepted transactions.
    pub receipts: Vec<TxReceipt>,
    /// Indices of transactions the t8n rejected, with reason. The index
    /// is into the original input txs list.
    pub rejected: Vec<RejectedTx>,
    /// Cumulative gas used across all accepted txs.
    pub gas_used: u64,
    /// Resolved block base fee (computed from parent if not provided).
    pub base_fee: u64,
    /// Resolved block excess blob gas (computed from parent if not
    /// provided), pre-EIP-4844 forks leave this `None`.
    pub excess_blob_gas: Option<u64>,
    /// Total blob gas used by blob-carrying txs in this block.
    pub blob_gas_used: u64,
    /// Block environment that was actually used for execution; useful
    /// for the output module when it builds the result JSON.
    pub block_env: BlockEnv,
    /// Fork spec used.
    pub spec_id: SpecId,
    /// EIP-7685 typed requests gathered after block execution.
    /// `Some(vec)` on Prague+, `None` pre-Prague. Each entry is
    /// already prefixed with its request-type byte (0x00 deposit,
    /// 0x01 withdrawal-queue, 0x02 consolidation-queue).
    pub requests: Option<Vec<Vec<u8>>>,
    /// Block-level exception emitted when a post-block system call
    /// reverts/halts. Mirrors geth's "system call failed to execute"
    /// path — invalidates the entire block. `None` means the block is
    /// valid at the post-block layer.
    pub block_exception: Option<String>,
    /// EIP-7928 Block-level Access List, RLP-encoded (Amsterdam+).
    /// `None` pre-Amsterdam.
    pub block_access_list: Option<Vec<u8>>,
    /// keccak256 of `block_access_list` (Amsterdam+).
    pub block_access_list_hash: Option<B256>,
}

/// Receipt for a single executed transaction.
pub struct TxReceipt {
    pub tx_type: u8,
    pub status: bool,
    pub gas_used: u64,
    pub cumulative_gas_used: u64,
    pub logs: Vec<Log>,
    pub contract_address: Option<Address>,
}

/// Record of a rejected tx (failed pre-validation or execution error).
pub struct RejectedTx {
    pub index: usize,
    pub error: String,
}

/// Execute a single block's worth of state transition.
pub fn execute(
    input: T8nInput,
    fork: &str,
    chain_id: u64,
) -> Result<ExecuteOutput, String> {
    let spec_id = fork_to_spec_id(fork)?;

    let mut cfg = CfgEnv::default();
    cfg.set_spec_and_mainnet_gas_params(spec_id);
    cfg.chain_id = chain_id;

    // EIP-4844 per-tx blob limit. At Cancun/Prague this equals the
    // per-block max (6 / 9). At Osaka (EIP-7594), per-tx max is 6
    // while per-block max stays 9 — so we MUST use the fork's
    // canonical `max_blobs_per_tx` rather than blob_params.max
    // (which is the per-block limit). Without this, Osaka accepts
    // type-3 txs with 7-9 blobs (test_invalid_max_blobs_per_tx).
    let per_tx_max: u64 = if spec_id.is_enabled_in(SpecId::OSAKA) {
        alloy_eips::eip7840::BlobParams::osaka().max_blobs_per_tx
    } else if spec_id.is_enabled_in(SpecId::PRAGUE) {
        alloy_eips::eip7840::BlobParams::prague().max_blobs_per_tx
    } else if spec_id.is_enabled_in(SpecId::CANCUN) {
        alloy_eips::eip7840::BlobParams::cancun().max_blobs_per_tx
    } else {
        0
    };
    if per_tx_max > 0 {
        cfg.set_max_blobs_per_tx(per_tx_max);
    }

    let (block_env, base_fee, excess_blob_gas) =
        build_block_env(&input.env, spec_id, input.blob_params.as_ref())?;

    // Initialise database from alloc.
    let mut state = State::builder().with_bal_builder().build();
    for (address, account) in &input.alloc {
        let code_bytes: Bytes = account.code.clone();
        let info = EvmAccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: keccak256(&code_bytes),
            code: Some(Bytecode::new_raw(code_bytes)),
            account_id: None,
        };
        state.insert_account_with_storage(
            *address,
            info,
            account.storage.clone(),
        );
    }
    // Seed known ancestor block hashes for the BLOCKHASH opcode.
    for (number, hash) in &input.env.block_hashes {
        let n: u64 = number.try_into().map_err(|_| {
            "block_hashes key does not fit in u64".to_string()
        })?;
        state.block_hashes.insert(n, *hash);
    }

    let evm_context = Context::mainnet()
        .with_block(&block_env)
        .with_cfg(cfg.clone())
        .with_db(&mut state);
    let mut evm = evm_context.build_mainnet();

    // EIP-7928 BAL index: reset to PRE_EXECUTION before the tx loop.
    // We bump once per tx (so tx i lands at the right index), then
    // once more before post-block so withdrawals / system-contract
    // requests are tagged with `len(txs) + 1` (EELS amsterdam
    // fork.py: post-execution index = ulen(transactions) + 1).
    evm.ctx_mut().db_mut().reset_bal_index();

    // Pre-block system calls (EIP-2935 history storage, EIP-4788 beacon root).
    pre_block_transition(
        &mut evm,
        spec_id,
        input.env.parent_hash,
        input.env.parent_beacon_block_root,
    )
    .map_err(|e| format!("pre-block system call: {e:?}"))?;

    let mut receipts: Vec<TxReceipt> = Vec::with_capacity(input.txs.len());
    let mut rejected: Vec<RejectedTx> = Vec::new();
    // `cumulative_gas` = Σ tx_gas_used (post-refund) — feeds receipt
    // cumulativeGasUsed (matches EELS `block_output.cumulative_gas_used`).
    let mut cumulative_gas: u64 = 0;
    // EIP-8037 / EIP-7778: the block header's gas_used is NOT the sum
    // of post-refund tx gas. It's `max(Σregular, Σstate)` (refunds not
    // applied to block gas). revm exposes the split via
    // `gas.block_regular_gas_used()` / `block_state_gas_used()`.
    let mut block_regular_gas: u64 = 0;
    let mut block_state_gas: u64 = 0;
    let mut blob_gas_used: u64 = 0;

    // Per-block blob gas budget (EIP-4844). Sourced from blobParams.max
    // when supplied; otherwise fall back to the spec's hardcoded max.
    // A tx whose inclusion would push the block over budget is rejected
    // with `TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED` (per geth t8n).
    let max_block_blob_gas: Option<u64> = if spec_id
        .is_enabled_in(SpecId::CANCUN)
    {
        let max_blobs = input
            .blob_params
            .as_ref()
            .and_then(|bp| bp.max.try_into().ok())
            .unwrap_or(
                revm::primitives::eip4844::MAX_BLOB_NUMBER_PER_BLOCK_CANCUN,
            );
        let max_blobs: u64 = max_blobs;
        Some(max_blobs * revm::primitives::eip4844::GAS_PER_BLOB)
    } else {
        None
    };

    for (idx, tx) in input.txs.iter().enumerate() {
        // Block-level cumulative gas check: a tx whose gas_limit
        // would push cumulative_gas past block_gas_limit gets rejected
        // pre-execution (matches reth/geth tx-pool wording and what
        // EIP-7825 tests expect — GAS_ALLOWANCE_EXCEEDED). revm's
        // own `CallerGasLimitMoreThanBlock` fires only on per-tx
        // gas_limit > block, not cumulative.
        let tx_gas_limit: u64 = tx.gas.try_into().unwrap_or(u64::MAX);
        if cumulative_gas.saturating_add(tx_gas_limit) > block_env.gas_limit {
            rejected.push(RejectedTx {
                index: idx,
                error: "caller gas limit exceeds the block gas limit"
                    .to_string(),
            });
            continue;
        }

        // Block-level blob gas budget check: reject any tx whose blobs
        // would push cumulative blob gas over the per-block max.
        let tx_blob_gas = (tx.blob_versioned_hashes.len() as u64)
            * revm::primitives::eip4844::GAS_PER_BLOB;
        if let Some(max) = max_block_blob_gas {
            if tx_blob_gas > 0 && blob_gas_used + tx_blob_gas > max {
                rejected.push(RejectedTx {
                    index: idx,
                    error: format!(
                        "blob gas used {} exceeds maximum allowance {}",
                        blob_gas_used + tx_blob_gas,
                        max
                    ),
                });
                continue;
            }
        }

        let tx_env = match build_tx_env(tx) {
            Ok(env) => env,
            Err(e) => {
                rejected.push(RejectedTx {
                    index: idx,
                    error: e,
                });
                continue;
            }
        };
        evm.ctx_mut().db_mut().bump_bal_index();
        match evm.transact(tx_env.clone()) {
            Ok(result) => {
                let gas = result.result.gas();
                let tx_gas = gas.tx_gas_used();
                cumulative_gas += tx_gas;
                block_regular_gas += gas.block_regular_gas_used();
                block_state_gas += gas.block_state_gas_used();
                let (status, logs, contract_address) = match &result.result {
                    ExecutionResult::Success { logs, output, .. } => {
                        let contract = match output {
                            Output::Create(_, addr) => *addr,
                            Output::Call(_) => None,
                        };
                        (true, logs.clone(), contract)
                    }
                    ExecutionResult::Revert { .. }
                    | ExecutionResult::Halt { .. } => {
                        (false, vec![], None)
                    }
                };
                receipts.push(TxReceipt {
                    tx_type: tx_type_to_u8(&tx.tx_type),
                    status,
                    gas_used: tx_gas,
                    cumulative_gas_used: cumulative_gas,
                    logs,
                    contract_address,
                });
                blob_gas_used += tx_blob_gas;
                evm.commit(result.state);
            }
            Err(e) => {
                // Emit Display, not Debug — the framework's exception
                // mapper does substring matching against the
                // human-readable error strings revm exposes via Display.
                rejected.push(RejectedTx {
                    index: idx,
                    error: format!("{e}"),
                });
            }
        }
    }

    // Convert our Withdrawal into the type the post-block helper expects.
    let withdrawals: Vec<TxWithdrawal> = input
        .env
        .withdrawals
        .iter()
        .map(|w| TxWithdrawal {
            index: w.index,
            validator_index: w.validator_index,
            address: w.address,
            amount: w.amount,
        })
        .collect();

    // EIP-7928: post-execution operations (withdrawals, EIP-7002 /
    // EIP-7251 system contracts) are tagged with block_access_index
    // `len(txs) + 1`. We've bumped once per tx in the loop above
    // (reset → 0, then N bumps → N); one more bump lands the
    // post-block phase at N+1, matching EELS amsterdam fork.py:899.
    evm.ctx_mut().db_mut().bump_bal_index();

    // Post-block: block reward, withdrawals, and the EIP-7002 /
    // EIP-7251 system calls. The system-call outputs are the request
    // bytes EIP-7685 needs, and a revert/halt of either becomes a
    // block-level exception (per geth's `core.PostExecution`).
    let post_block =
        post_block_transition(&mut evm, &block_env, &withdrawals, spec_id)
            .map_err(|e| format!("post-block system call: {e:?}"))?;
    let mut block_exception = post_block.block_exception;
    let requests = if spec_id.is_enabled_in(SpecId::PRAGUE) {
        let mut all = match gather_eip6110_deposit_requests(&receipts) {
            DepositGather::Ok(reqs) => reqs,
            DepositGather::InvalidLayout => {
                if block_exception.is_none() {
                    block_exception = Some(
                        "failed to decode deposit requests from receipts"
                            .to_string(),
                    );
                }
                Vec::new()
            }
        };
        all.extend(post_block.requests);
        Some(all)
    } else {
        None
    };

    drop(evm);

    // EIP-7928 Block-level Access List (Amsterdam+). revm accumulated
    // it automatically (state built with `with_bal_builder()`, tx
    // index bumped per tx). Take the alloy-typed BAL, canonicalise
    // ordering (EELS emits a sorted BAL), then RLP-encode and hash.
    // The framework re-decodes our RLP, re-encodes, and checks
    // keccak256 == our block_access_list_hash, so both must be
    // derived from the same canonical bytes.
    let (block_access_list, block_access_list_hash) =
        if spec_id.is_enabled_in(SpecId::AMSTERDAM) {
            // `take_built_alloy_bal` already returns a canonically
            // ordered EIP-7928 BAL (accounts sorted by address, nested
            // reads/changes sorted) — no further sorting needed. Use
            // revm's pinned alloy_eip7928 type directly so there's no
            // dependency-version mismatch.
            let alloy_bal =
                state.take_built_alloy_bal().unwrap_or_default();
            // EIP-7928: the BAL is bounded by the block gas limit.
            // Each account contributes one item plus one per unique
            // storage slot (reads ∪ writes); if the total exceeds
            // `block_gas_limit // BLOCK_ACCESS_LIST_ITEM` the block is
            // invalid (EELS amsterdam block_access_lists.py:
            // validate_block_access_list_gas_limit).
            let bal_items = revm::state::bal::alloy::total_alloy_bal_items(
                &alloy_bal,
            );
            let bal_item_budget =
                block_env.gas_limit / BLOCK_ACCESS_LIST_ITEM_GAS;
            if bal_items > bal_item_budget && block_exception.is_none() {
                block_exception =
                    Some("block access list exceeds gas limit".to_string());
            }
            let mut rlp = Vec::new();
            alloy_rlp::encode_list(&alloy_bal, &mut rlp);
            let hash = revm::primitives::keccak256(&rlp);
            (Some(rlp), Some(hash))
        } else {
            (None, None)
        };

    // EIP-8037/EIP-7778: block header gas_used diverges from the
    // refund-applied cumulative tx gas at Amsterdam+.
    let block_gas_used = if spec_id.is_enabled_in(SpecId::AMSTERDAM) {
        block_regular_gas.max(block_state_gas)
    } else {
        cumulative_gas
    };

    Ok(ExecuteOutput {
        state,
        receipts,
        rejected,
        gas_used: block_gas_used,
        base_fee,
        excess_blob_gas,
        blob_gas_used,
        block_env,
        spec_id,
        requests,
        block_exception,
        block_access_list,
        block_access_list_hash,
    })
}

/// Result of EIP-6110 deposit-log gathering.
pub enum DepositGather {
    /// `Ok(requests)` — entries to add to the EIP-7685 requests list.
    /// Empty Vec means no deposit logs were emitted.
    Ok(Vec<Vec<u8>>),
    /// At least one deposit log was emitted with an invalid layout
    /// (bogus ABI offsets/lengths). The whole block is invalid.
    /// String mirrors the wording the framework's exception mapper
    /// uses for `INVALID_DEPOSIT_EVENT_LAYOUT`.
    InvalidLayout,
}

/// EIP-6110: walk per-tx receipts for `DepositEvent` logs emitted by the
/// beacon deposit contract and pack them into a single 0x00-typed
/// request entry (mirrors geth's `ParseDepositLogs`).
///
/// Unlike geth — which only length-checks — we also validate the ABI
/// offsets and length headers match the canonical layout, because the
/// framework's `test_invalid_layout` tests verify that a modified
/// deposit contract emitting malformed logs gets the block rejected
/// with `INVALID_DEPOSIT_EVENT_LAYOUT`.
fn gather_eip6110_deposit_requests(receipts: &[TxReceipt]) -> DepositGather {
    use revm::primitives::address;
    let deposit_contract: Address =
        address!("0x00000000219ab540356cbb839cbe05303d7705fa");
    let deposit_topic: B256 = revm::primitives::b256!(
        "0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5"
    );

    let mut deposits: Vec<u8> = vec![0x00]; // request type prefix
    for r in receipts {
        for log in &r.logs {
            if log.address != deposit_contract {
                continue;
            }
            let topics = log.topics();
            if topics.is_empty() || topics[0] != deposit_topic {
                continue;
            }
            match deposit_log_to_request(&log.data.data) {
                Some(packed) => deposits.extend_from_slice(&packed),
                None => return DepositGather::InvalidLayout,
            }
        }
    }

    if deposits.len() > 1 {
        DepositGather::Ok(vec![deposits])
    } else {
        DepositGather::Ok(Vec::new())
    }
}

/// Port of geth's `DepositLogToRequest` (`core/types/deposit.go`),
/// extended with ABI-layout validation.
///
/// Unpacks the 576-byte ABI-encoded `DepositEvent(pubkey,
/// withdrawal_creds, amount, signature, index)` into the 192-byte
/// packed deposit request: `pubkey(48) || withdrawal_creds(32) ||
/// amount(8) || signature(96) || index(8)`.
///
/// Returns `None` if any of the ABI offsets / length headers diverge
/// from the canonical layout. The framework's modified-contract
/// tests rely on this rejection path to trigger
/// `INVALID_DEPOSIT_EVENT_LAYOUT`.
fn deposit_log_to_request(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() != 576 {
        return None;
    }
    // Canonical `DepositEvent(bytes,bytes,bytes,bytes,bytes)` layout:
    //   data[0..0xa0]: five 32-byte offsets → 0xa0, 0x100, 0x140,
    //                   0x180, 0x200 (positions of each field)
    //   data[offset..offset+32]: length header → 0x30, 0x20, 0x08,
    //                            0x60, 0x08 (field byte lengths)
    // Anything else is a malformed event from a modified contract.
    const EXPECTED: &[(usize, u8)] = &[
        // offset slots: high 31 bytes must be zero, last byte = value
        (0x1f, 0xa0),
        (0x3f, 0x00), // offset 0x100 = 256; only bit 8 set, not in last byte
        (0x5f, 0x40),
        (0x7f, 0x80),
        (0x9f, 0x00), // offset 0x200; bit 9 only
    ];
    // Offsets are 32-byte big-endian U256. Validate exact values
    // 0xa0, 0x100, 0x140, 0x180, 0x200 by comparing to fixed-byte
    // patterns: all high bytes zero, then two low bytes matching.
    let canonical_offsets: [[u8; 2]; 5] = [
        [0x00, 0xa0],
        [0x01, 0x00],
        [0x01, 0x40],
        [0x01, 0x80],
        [0x02, 0x00],
    ];
    for (i, want_lo) in canonical_offsets.iter().enumerate() {
        let slot = &data[i * 32..(i + 1) * 32];
        // First 30 bytes must be zero (offset fits in u16).
        if slot[0..30].iter().any(|&b| b != 0) {
            return None;
        }
        if slot[30] != want_lo[0] || slot[31] != want_lo[1] {
            return None;
        }
    }
    let _ = EXPECTED; // (unused — left as documentation of intent)

    // Length headers at each field's offset.
    let canonical_lengths: [(usize, u8); 5] = [
        (0xa0, 0x30),  // pubkey: 48
        (0x100, 0x20), // withdrawal_creds: 32
        (0x140, 0x08), // amount: 8
        (0x180, 0x60), // signature: 96
        (0x200, 0x08), // index: 8
    ];
    for (pos, want) in canonical_lengths.iter() {
        let slot = &data[*pos..*pos + 32];
        if slot[0..31].iter().any(|&b| b != 0) {
            return None;
        }
        if slot[31] != *want {
            return None;
        }
    }

    let mut out = vec![0u8; 192];
    // Repack body bytes at known canonical positions.
    let mut b = 32 * 5 + 32;
    out[0..48].copy_from_slice(&data[b..b + 48]);
    b += 48 + 16 + 32;
    out[48..80].copy_from_slice(&data[b..b + 32]);
    b += 32 + 32;
    out[80..88].copy_from_slice(&data[b..b + 8]);
    b += 8 + 24 + 32;
    out[88..184].copy_from_slice(&data[b..b + 96]);
    b += 96 + 32;
    out[184..192].copy_from_slice(&data[b..b + 8]);
    Some(out)
}

/// Build a [`BlockEnv`] from the parsed [`EnvInput`]. Computes
/// `current_base_fee` and `current_excess_blob_gas` from parent fields
/// when the input doesn't already provide them (matches geth t8n
/// behaviour — the framework usually only supplies parent fields).
fn build_block_env(
    env: &EnvInput,
    spec: SpecId,
    blob_params: Option<&super::input::BlobParams>,
) -> Result<(BlockEnv, u64, Option<u64>), String> {
    // base fee
    let base_fee = if let Some(bf) = env.current_base_fee {
        bf.try_into().map_err(|_| "current_base_fee overflows u64".to_string())?
    } else if spec.is_enabled_in(SpecId::LONDON) {
        let parent_base_fee = env
            .parent_base_fee
            .ok_or_else(|| "parent_base_fee required on London+".to_string())?
            .try_into()
            .map_err(|_| "parent_base_fee overflows u64".to_string())?;
        let parent_gas_used: u64 = env
            .parent_gas_used
            .unwrap_or(U256::ZERO)
            .try_into()
            .map_err(|_| "parent_gas_used overflows u64".to_string())?;
        let parent_gas_limit: u64 = env
            .parent_gas_limit
            .unwrap_or(U256::ZERO)
            .try_into()
            .map_err(|_| "parent_gas_limit overflows u64".to_string())?;
        calc_next_block_base_fee(
            parent_gas_used,
            parent_gas_limit,
            parent_base_fee,
            BaseFeeParams::ethereum(),
        )
    } else {
        0
    };

    // excess blob gas — computed by alloy's `next_block_excess_blob_gas_osaka`,
    // which handles all forks: pre-Osaka collapses to `max(0,
    // parent_excess + parent_used - target_blob_gas)`; Osaka adds the
    // EIP-7918 base-fee-floor branch and needs the current base fee.
    let excess_blob_gas = if let Some(ebg) = env.current_excess_blob_gas {
        Some(
            ebg.try_into()
                .map_err(|_| "current_excess_blob_gas overflows u64".to_string())?,
        )
    } else if spec.is_enabled_in(SpecId::CANCUN) {
        let parent_excess: u64 = env
            .parent_excess_blob_gas
            .unwrap_or(U256::ZERO)
            .try_into()
            .map_err(|_| "parent_excess_blob_gas overflows u64".to_string())?;
        let parent_used: u64 = env
            .parent_blob_gas_used
            .unwrap_or(U256::ZERO)
            .try_into()
            .map_err(|_| "parent_blob_gas_used overflows u64".to_string())?;

        let alloy_params = if let Some(bp) = blob_params {
            let target: u64 = bp.target.try_into().unwrap_or(0);
            let max: u64 = bp.max.try_into().unwrap_or(target);
            let mut base = if spec.is_enabled_in(SpecId::OSAKA) {
                alloy_eips::eip7840::BlobParams::osaka()
            } else if spec.is_enabled_in(SpecId::PRAGUE) {
                alloy_eips::eip7840::BlobParams::prague()
            } else {
                alloy_eips::eip7840::BlobParams::cancun()
            };
            base.target_blob_count = target;
            base.max_blob_count = max;
            base.max_blobs_per_tx = max;
            // Framework-supplied baseFeeUpdateFraction takes precedence
            // over the alloy fork default. The values differ for BPO
            // forks (e.g. BPO1 vs Osaka have different update_fractions)
            // and even Osaka itself uses 5007460 in the framework vs
            // 5007716 in alloy — using alloy's value breaks the
            // EIP-7918 threshold math at fork transitions.
            if let Ok(f) = bp.base_fee_update_fraction.try_into() {
                let f: u128 = f;
                if f > 0 {
                    base.update_fraction = f;
                }
            }
            base
        } else if spec.is_enabled_in(SpecId::OSAKA) {
            alloy_eips::eip7840::BlobParams::osaka()
        } else if spec.is_enabled_in(SpecId::PRAGUE) {
            alloy_eips::eip7840::BlobParams::prague()
        } else {
            alloy_eips::eip7840::BlobParams::cancun()
        };
        // EIP-7918 threshold uses the PARENT block's base_fee_per_gas
        // (the comparison is based on settled state, not the block
        // we're computing for). EELS confirms this at
        // `osaka/vm/gas.py::calculate_excess_blob_gas` line 418 —
        // `base_fee_per_gas = parent_header.base_fee_per_gas`. Passing
        // the current block's base_fee here puts us 2 wei below the
        // threshold for the parent_excess_blobs_6 / base_fee_17 case
        // and the formula returns 0 instead of the parent excess.
        let parent_base_fee: u64 = env
            .parent_base_fee
            .unwrap_or(U256::ZERO)
            .try_into()
            .map_err(|_| "parent_base_fee overflows u64".to_string())?;
        Some(alloy_params.next_block_excess_blob_gas_osaka(
            parent_excess,
            parent_used,
            parent_base_fee,
        ))
    } else {
        None
    };

    let blob_excess_gas_and_price = excess_blob_gas.map(|ebg| {
        let update_fraction = if let Some(bp) = blob_params {
            bp.base_fee_update_fraction
                .try_into()
                .unwrap_or(BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE)
        } else if spec.is_enabled_in(SpecId::PRAGUE) {
            BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE
        } else {
            BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN
        };
        BlobExcessGasAndPrice::new(ebg, update_fraction)
    });

    let prevrandao = if spec.is_enabled_in(SpecId::MERGE) {
        Some(env.current_random.unwrap_or(B256::ZERO))
    } else {
        None
    };

    let block = BlockEnv {
        number: env.current_number,
        beneficiary: env.current_coinbase,
        timestamp: env.current_timestamp,
        gas_limit: env
            .current_gas_limit
            .try_into()
            .map_err(|_| "current_gas_limit overflows u64".to_string())?,
        basefee: base_fee,
        difficulty: env.current_difficulty.unwrap_or(U256::ZERO),
        prevrandao,
        blob_excess_gas_and_price,
        slot_num: env
            .slot_number
            .and_then(|s| s.try_into().ok())
            .unwrap_or(0),
    };

    Ok((block, base_fee, excess_blob_gas))
}

fn tx_type_to_u8(v: &U256) -> u8 {
    v.try_into().unwrap_or(0)
}

fn build_tx_env(tx: &TxInput) -> Result<TxEnv, String> {
    let tx_type = tx_type_to_u8(&tx.tx_type);
    let kind = match tx.to {
        Some(to) => TxKind::Call(to),
        None => TxKind::Create,
    };
    let sender = tx
        .sender
        .ok_or_else(|| "tx missing recovered sender".to_string())?;

    let mut builder = TxEnv::builder()
        .tx_type(Some(tx_type))
        .caller(sender)
        .gas_limit(
            tx.gas
                .try_into()
                .map_err(|_| "tx gas overflows u64".to_string())?,
        )
        .nonce(
            tx.nonce
                .try_into()
                .map_err(|_| "tx nonce overflows u64".to_string())?,
        )
        .value(tx.value)
        .data(tx.input.clone())
        .kind(kind);

    if !tx.access_list.is_empty() {
        let access_list: revm::context_interface::transaction::AccessList = tx
            .access_list
            .iter()
            .map(|e| revm::context_interface::transaction::AccessListItem {
                address: e.address,
                storage_keys: e.storage_keys.clone(),
            })
            .collect::<Vec<_>>()
            .into();
        builder = builder.access_list(access_list);
    }
    if !tx.blob_versioned_hashes.is_empty() {
        builder = builder.blob_hashes(tx.blob_versioned_hashes.clone());
    }
    if let Some(max_blob) = tx.max_fee_per_blob_gas {
        builder = builder.max_fee_per_blob_gas(
            max_blob
                .try_into()
                .map_err(|_| "max_fee_per_blob_gas overflows u128".to_string())?,
        );
    }

    // EIP-7702 authorization list. We unconditionally pass the auth
    // list (even when empty) for type-4 txs so revm can apply the
    // EmptyAuthorizationList rejection. The empty-but-passed-through
    // distinction is what `test_empty_authorization_list` exercises.
    if tx_type == 4 || !tx.authorization_list.is_empty() {
        use revm::context_interface::transaction::{
            Authorization as RevmAuthorization, SignedAuthorization,
        };
        let auths: Vec<SignedAuthorization> = tx
            .authorization_list
            .iter()
            .map(|a| {
                let inner = RevmAuthorization {
                    chain_id: a.chain_id,
                    address: a.address,
                    nonce: a.nonce.try_into().unwrap_or(u64::MAX),
                };
                let y_parity: u8 = a.v.try_into().unwrap_or(0);
                SignedAuthorization::new_unchecked(inner, y_parity, a.r, a.s)
            })
            .collect();
        builder = builder.authorization_list_signed(auths);
    }

    if let Some(chain_id) = tx.chain_id {
        let cid: u64 = chain_id
            .try_into()
            .map_err(|_| "chain_id overflows u64".to_string())?;
        if cid != 0 {
            builder = builder.chain_id(Some(cid));
        }
    }

    builder = match tx_type {
        0 | 1 => {
            if let Some(gp) = tx.gas_price {
                builder.gas_price(
                    gp.try_into()
                        .map_err(|_| "gas_price overflows u128".to_string())?,
                )
            } else {
                builder
            }
        }
        2..=4 => {
            let mut b = builder;
            if let Some(max_fee) = tx.max_fee_per_gas {
                b = b.gas_price(
                    max_fee
                        .try_into()
                        .map_err(|_| "max_fee_per_gas overflows u128".to_string())?,
                );
            }
            if let Some(prio) = tx.max_priority_fee_per_gas {
                b = b.gas_priority_fee(Some(
                    prio.try_into().map_err(|_| {
                        "max_priority_fee_per_gas overflows u128".to_string()
                    })?,
                ));
            }
            b
        }
        _ => builder,
    };

    builder
        .build()
        .map_err(|e| format!("build TxEnv: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::t8n::input::load;

    /// End-to-end smoke: parse the captured framework bundle and run
    /// execute() against it. Pre-block hooks must succeed; tx execution
    /// (one legacy COINBASE-target tx) must either succeed or be
    /// rejected with a captured reason — the assertion is that we don't
    /// crash.
    #[test]
    fn executes_captured_bundle() {
        let bundle: super::super::input::StdinBundle = serde_json::from_str(
            include_str!("../../../tests/data/t8n_sample_bundle.json"),
        )
        .expect("parse sample bundle");
        let tx_count = bundle.txs.as_ref().map_or(0, |t| t.len());
        let input = T8nInput {
            alloc: bundle.alloc.unwrap(),
            env: bundle.env.unwrap(),
            txs: bundle.txs.unwrap_or_default(),
            blob_params: bundle.blob_params,
        };
        let output =
            execute(input, "Osaka", 1).expect("execute block");
        // All input txs are accounted for one way or another.
        assert_eq!(output.receipts.len() + output.rejected.len(), tx_count);
    }
}
