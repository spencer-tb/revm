use revm::{
    context::{Block, ContextTr, JournalTr},
    context_interface::result::ExecutionResult,
    handler::EvmTr,
    primitives::{
        address, hardfork::SpecId, Address, Bytes, KECCAK_EMPTY, ONE_ETHER, ONE_GWEI, U256,
    },
    statetest_types::blockchain::Withdrawal,
    Database, DatabaseCommit, SystemCallCommitEvm,
};

/// Output of [`post_block_transition`].
pub struct PostBlockOutput {
    /// EIP-7685 typed-request payloads captured from the EIP-7002 /
    /// EIP-7251 system calls, each already prefixed with its
    /// request-type byte (`0x01` withdrawal-queue, `0x02`
    /// consolidation-queue). Empty pre-Prague; an empty system-call
    /// return is omitted.
    pub requests: Vec<Vec<u8>>,
    /// Block-level exception message, set if an EIP-7002 / EIP-7251
    /// system call reverted, halted, or ran out of gas. Per geth, a
    /// failed system call invalidates the entire block. `None` means
    /// the post-block work succeeded.
    pub block_exception: Option<String>,
}

/// Post block transition that includes:
///   * Block and uncle rewards before the Merge/Paris hardfork.
///   * Withdrawals (EIP-4895)
///   * Post-block system calls: EIP-7002 (withdrawal requests) and EIP-7251 (consolidation requests)
///
/// Captures the EIP-7685 typed-request payloads and any block-level
/// exception from a failing system call. Shape mirrors geth's
/// `core.PostExecution`.
///
/// # Note
///
/// Uncle rewards are not implemented yet.
#[inline]
pub fn post_block_transition<
    'a,
    DB: Database + DatabaseCommit + 'a,
    EVM: SystemCallCommitEvm<
            Error: core::fmt::Debug,
            ExecutionResult = ExecutionResult,
        > + EvmTr<Context: ContextTr<Db = DB>>,
>(
    evm: &mut EVM,
    block: impl Block,
    withdrawals: &[Withdrawal],
    spec: SpecId,
) -> Result<PostBlockOutput, EVM::Error> {
    // block reward
    let block_reward = block_reward(spec, 0);
    if block_reward != 0 {
        evm.ctx_mut()
            .journal_mut()
            .balance_incr(block.beneficiary(), U256::from(block_reward))
            .expect("Db actions to pass");
    }

    // withdrawals
    if spec.is_enabled_in(SpecId::SHANGHAI) {
        for withdrawal in withdrawals {
            evm.ctx_mut()
                .journal_mut()
                .balance_incr(
                    withdrawal.address,
                    withdrawal.amount.saturating_mul(U256::from(ONE_GWEI)),
                )
                .expect("Db actions to pass");
        }
    }

    evm.commit_inner();

    let mut requests: Vec<Vec<u8>> = Vec::new();
    let mut block_exception: Option<String> = None;

    // EIP-7002: Withdrawal requests system call.
    // Pre-check: if the predeploy address has no code (e.g. fork
    // activation before deployment), the block is invalid with
    // SYSTEM_CONTRACT_EMPTY. Otherwise: invoke the system call;
    // successful return bytes prefixed with 0x01 form the withdrawal-
    // queue request entry; empty return = no entry; revert/halt
    // invalidates the block (SYSTEM_CONTRACT_CALL_FAILED).
    if spec.is_enabled_in(SpecId::PRAGUE) {
        if system_contract_is_empty(evm, WITHDRAWAL_REQUEST_ADDRESS) {
            block_exception = Some("system contract empty".to_string());
        } else {
            let result = evm
                .system_call_commit(WITHDRAWAL_REQUEST_ADDRESS, Bytes::new())?;
            match result {
                ExecutionResult::Success { output, .. } => {
                    let payload = output.into_data();
                    if !payload.is_empty() {
                        let mut entry = Vec::with_capacity(payload.len() + 1);
                        entry.push(0x01);
                        entry.extend_from_slice(&payload);
                        requests.push(entry);
                    }
                }
                ExecutionResult::Revert { .. }
                | ExecutionResult::Halt { .. } => {
                    block_exception = Some(
                        "failed to apply withdrawal requests contract call"
                            .to_string(),
                    );
                }
            }
        }
    }

    // EIP-7251: Consolidation requests system call (0x02 prefix).
    if spec.is_enabled_in(SpecId::PRAGUE) && block_exception.is_none() {
        if system_contract_is_empty(evm, CONSOLIDATION_REQUEST_ADDRESS) {
            block_exception = Some("system contract empty".to_string());
        } else {
            let result = evm
                .system_call_commit(CONSOLIDATION_REQUEST_ADDRESS, Bytes::new())?;
            match result {
                ExecutionResult::Success { output, .. } => {
                    let payload = output.into_data();
                    if !payload.is_empty() {
                        let mut entry = Vec::with_capacity(payload.len() + 1);
                        entry.push(0x02);
                        entry.extend_from_slice(&payload);
                        requests.push(entry);
                    }
                }
                ExecutionResult::Revert { .. }
                | ExecutionResult::Halt { .. } => {
                    block_exception = Some(
                        "failed to apply consolidation requests contract call"
                            .to_string(),
                    );
                }
            }
        }
    }

    Ok(PostBlockOutput {
        requests,
        block_exception,
    })
}

/// Block reward for a block.
#[inline]
pub const fn block_reward(spec: SpecId, ommers: usize) -> u128 {
    if spec.is_enabled_in(SpecId::MERGE) {
        return 0;
    }

    let reward = if spec.is_enabled_in(SpecId::PETERSBURG) {
        ONE_ETHER * 2
    } else if spec.is_enabled_in(SpecId::BYZANTIUM) {
        ONE_ETHER * 3
    } else {
        ONE_ETHER * 5
    };

    reward + (reward >> 5) * ommers as u128
}

/// Check whether a predeploy address has empty code in the current
/// state. The framework treats a Prague+ block whose system contracts
/// haven't been deployed yet as invalid (`SYSTEM_CONTRACT_EMPTY`).
fn system_contract_is_empty<EVM>(evm: &mut EVM, addr: Address) -> bool
where
    EVM: EvmTr<Context: ContextTr>,
    <<EVM as EvmTr>::Context as ContextTr>::Db: Database,
{
    let db = evm.ctx_mut().db_mut();
    match db.basic(addr) {
        Ok(Some(account)) => {
            account.code_hash == KECCAK_EMPTY
                || account.code.as_ref().is_none_or(|c| c.is_empty())
        }
        Ok(None) => true,
        Err(_) => false, // db error: don't claim empty
    }
}

pub const WITHDRAWAL_REQUEST_ADDRESS: Address =
    address!("0x00000961Ef480Eb55e80D19ad83579A64c007002");

/// EIP-7002: Withdrawal requests system call.
///
/// Returns `Some(payload)` with the bytes produced by the system
/// contract on success, or `None` if the call halted/reverted. The
/// payload is *not* prefixed with the EIP-7685 request-type byte —
/// callers building EIP-7685 requests add the `0x01` prefix.
pub(crate) fn system_call_eip7002_withdrawal_request<EVM>(
    evm: &mut EVM,
) -> Result<Option<Bytes>, EVM::Error>
where
    EVM: SystemCallCommitEvm<Error: core::fmt::Debug, ExecutionResult = ExecutionResult>,
{
    // empty data is valid for EIP-7002
    let result = evm.system_call_commit(WITHDRAWAL_REQUEST_ADDRESS, Bytes::new())?;
    Ok(result.into_output())
}

pub const CONSOLIDATION_REQUEST_ADDRESS: Address =
    address!("0x0000BBdDc7CE488642fb579F8B00f3a590007251");

/// EIP-7251: Consolidation requests system call.
///
/// Returns `Some(payload)` with the bytes produced by the system
/// contract on success, or `None` if the call halted/reverted. The
/// payload is *not* prefixed with the EIP-7685 request-type byte —
/// callers building EIP-7685 requests add the `0x02` prefix.
pub(crate) fn system_call_eip7251_consolidation_request<EVM>(
    evm: &mut EVM,
) -> Result<Option<Bytes>, EVM::Error>
where
    EVM: SystemCallCommitEvm<Error: core::fmt::Debug, ExecutionResult = ExecutionResult>,
{
    let result = evm.system_call_commit(CONSOLIDATION_REQUEST_ADDRESS, Bytes::new())?;
    Ok(result.into_output())
}
