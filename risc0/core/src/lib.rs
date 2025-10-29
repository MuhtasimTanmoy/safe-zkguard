extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use bincode::Options;
use risc0_zkvm::sha::{Impl, Sha256};
use rs_merkle::Hasher as MerkleHasher;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tiny_keccak::Keccak;

////////////////////////////////////////////////////////////////
//  Public constants
////////////////////////////////////////////////////////////////
pub mod constants {
    //! Values that both guest and host need.

    /// function selector for `transfer(address,uint256)`
    pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    /// selector for `contractCall(address,uint256,bytes)`
    pub const CONTRACTCALL_SELECTOR: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];
}

////////////////////////////////////////////////////////////////
//  Helper types & functions
////////////////////////////////////////////////////////////////

/// Keccak-256 convenience wrapper
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::Hasher;

    let mut k = Keccak::v256();
    k.update(bytes);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[derive(Clone)]
pub struct Sha256MerkleHasher;

impl MerkleHasher for Sha256MerkleHasher {
    // Fixed size 32-byte hash
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        // Convert the resulting byte slice `&[u8]` into a fixed-size array `[u8; 32]`
        Impl::hash_bytes(data).as_bytes().try_into().unwrap()
    }
}

/// Canonicalises a map of lists: sorts addresses ascending (dedup) and uses
/// a `BTreeMap` so keys are ordered. Returns `(canonical, bytes)` where
/// `bytes` is the bincode (fixint) serialization of the canonical structure.
pub fn canonicalise_lists(
    raw: BTreeMap<String, Vec<[u8; 20]>>,
) -> (BTreeMap<String, Vec<[u8; 20]>>, Vec<u8>) {
    use bincode::Options;
    let mut canon: BTreeMap<String, Vec<[u8; 20]>> = BTreeMap::new();
    for (key, mut value) in raw.into_iter() {
        value.sort();
        value.dedup();
        canon.insert(key, value);
    }
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&canon)
        .expect("canonical serialise");
    (canon, bytes)
}

/// Very small, fixed-layout ABI decoder for the two hard-coded
/// selectors. Returns [`Action`] on success.
pub fn parse_action<'a>(target: &[u8], data: &'a [u8]) -> Option<Action> {
    use constants::*;
    let sel = data.get(..4)?;

    if sel == TRANSFER_SELECTOR {
        let to: [u8; 20] = data.get(16..36)?.try_into().ok()?;

        let mut amt = [0u8; 16];
        amt.copy_from_slice(data.get(52..68)?);
        let amount = u128::from_be_bytes(amt);

        let erc20_address: [u8; 20] = target.try_into().ok()?;
        Some(Action::Transfer {
            erc20_address,
            to,
            amount,
        })
    } else {
        None
    }
}

// Bincode-serialization of the PolicyLine and SHA-256 hash of the result.
pub fn hash_policy_line_for_merkle_tree(pl: &PolicyLine) -> [u8; 32] {
    // Serialize the PolicyLine into bytes.
    let policy_line_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(pl)
        .expect("Failed to bincode serialize PolicyLine for hashing");

    // Hash the resulting bytes
    sha2::Sha256::digest(&policy_line_bytes).into()
}

/*───────────────────────────────────────────────────────────────────────────*
 * Data Structures                                                          *
 *───────────────────────────────────────────────────────────────────────────*/
/// Compact action enum produced by [`parse_action`]
#[derive(Clone, Copy, Debug)]
pub enum Action {
    Transfer {
        erc20_address: [u8; 20],
        to: [u8; 20],
        amount: u128,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxType {
    Transfer,
    ContractCall,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DestinationPattern {
    /// Matches any address.
    Any,
    /// Matches a specific address.
    Exact([u8; 20]),
    /// Matches if the address is contained in the named group.
    Group(String),
    /// Matches if the address is contained in the named allow-list.
    Allowlist(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignerPattern {
    /// Matches any signer.
    Any,
    /// Matches a specific address.
    Exact([u8; 20]),
    /// Matches if the signer is contained in the named group.
    Group(String),
    /// Matches if a threshold of signers from the named group have signed.
    Threshold { group: String, threshold: u8 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssetPattern {
    /// Wildcard – matches any asset.
    Any,
    /// Exact contract address of the asset.
    Exact([u8; 20]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Allow,
    Block,
}

/// One line in the policy (ordered by the `id` field).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyLine {
    pub id: u32,
    pub tx_type: TxType,
    pub destination: DestinationPattern,
    pub signer: SignerPattern,
    pub asset: AssetPattern,
    pub amount_max: Option<u128>,
    pub function_selector: Option<[u8; 4]>,
}

/// Canonical pseudo-address used to represent native ETH transfers.
pub const ETH_ASSET: [u8; 20] = [0u8; 20];

/// Complete description of a signed user operation that is about to be
/// executed on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserAction {
    pub from: [u8; 20],           // contract address initiating the action
    pub to: [u8; 20],             // target contract or direct recipient
    pub value: u128,              // native token amount (wei)
    pub nonce: u64,               // Safe's current nonce for replay protection
    pub data: Vec<u8>,            // calldata
    pub signatures: Vec<Vec<u8>>, // one or more ECDSA signatures + recovery id
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    pub leaf_index: u64,         // The 0-based index of the leaf from the left
    pub siblings: Vec<[u8; 32]>, // The sibling hashes from bottom to top
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    root: [u8; 32],
    action: UserAction,
}
