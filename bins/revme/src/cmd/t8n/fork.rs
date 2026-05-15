//! Fork-name → [`SpecId`] mapping for t8n inputs.
//!
//! The framework passes fork names verbatim via `--state.fork`. Match the
//! exact strings the execution-spec-tests framework emits from
//! `Fork.transition_tool_name()`. Transition forks resolve to the fork
//! they transition *to*, since by the time the t8n is called the block
//! number is past the transition point.

use revm::primitives::hardfork::SpecId;

/// Resolve a fork name to a [`SpecId`].
pub fn fork_to_spec_id(fork: &str) -> Result<SpecId, String> {
    Ok(match fork {
        "Frontier" => SpecId::FRONTIER,
        "Homestead" => SpecId::HOMESTEAD,
        "EIP150" | "Tangerine" => SpecId::TANGERINE,
        "EIP158" | "SpuriousDragon" => SpecId::SPURIOUS_DRAGON,
        "Byzantium" => SpecId::BYZANTIUM,
        "Constantinople" | "ConstantinopleFix" | "Petersburg" => SpecId::PETERSBURG,
        "Istanbul" => SpecId::ISTANBUL,
        "Berlin" => SpecId::BERLIN,
        "London" => SpecId::LONDON,
        "Paris" | "Merge" => SpecId::MERGE,
        "Shanghai" => SpecId::SHANGHAI,
        "Cancun" => SpecId::CANCUN,
        "Prague" => SpecId::PRAGUE,
        "Osaka" => SpecId::OSAKA,
        "Amsterdam" => SpecId::AMSTERDAM,
        // Transition forks resolve to the destination fork.
        "ByzantiumToConstantinopleAt5" => SpecId::PETERSBURG,
        "ParisToShanghaiAtTime15k" => SpecId::SHANGHAI,
        "ShanghaiToCancunAtTime15k" => SpecId::CANCUN,
        "CancunToPragueAtTime15k" => SpecId::PRAGUE,
        "PragueToOsakaAtTime15k" => SpecId::OSAKA,
        "OsakaToBPO1AtTime15k" => SpecId::OSAKA,
        "BPO1ToBPO2AtTime15k" => SpecId::OSAKA,
        "BPO2ToBPO3AtTime15k" => SpecId::OSAKA,
        "BPO3ToBPO4AtTime15k" => SpecId::OSAKA,
        "BPO4ToBPO5AtTime15k" => SpecId::OSAKA,
        "BPO5ToAmsterdamAtTime15k" => SpecId::AMSTERDAM,
        "BPO2ToAmsterdamAtTime15k" => SpecId::AMSTERDAM,
        // BPO forks share the OSAKA SpecId (blob parameter optimisation
        // only changes blob schedule, not consensus rules).
        "BPO1" | "BPO2" | "BPO3" | "BPO4" | "BPO5" => SpecId::OSAKA,
        other => {
            return Err(format!("unsupported fork: {other}"));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_forks_resolve() {
        assert_eq!(fork_to_spec_id("Osaka").unwrap(), SpecId::OSAKA);
        assert_eq!(fork_to_spec_id("Prague").unwrap(), SpecId::PRAGUE);
        assert_eq!(fork_to_spec_id("Cancun").unwrap(), SpecId::CANCUN);
        assert_eq!(
            fork_to_spec_id("PragueToOsakaAtTime15k").unwrap(),
            SpecId::OSAKA
        );
    }

    #[test]
    fn unknown_fork_errors() {
        assert!(fork_to_spec_id("MadeUpFork").is_err());
    }
}
