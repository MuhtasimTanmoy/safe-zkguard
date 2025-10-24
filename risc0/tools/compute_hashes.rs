use anyhow::{Context, Result};
use bincode::Options;
use rs_merkle::MerkleTree;
use serde::Deserialize;
use k256::sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::BufReader;
use zkguard_core::{
    hash_policy_line_for_merkle_tree, AssetPattern as CoreAssetPattern, DestinationPattern as CoreDestinationPattern,
    PolicyLine as CorePolicyLine, Sha256MerkleHasher, SignerPattern as CoreSignerPattern, TxType as CoreTxType,
};

#[derive(Deserialize, Debug, Clone)]
struct JsonPolicyLine {
    id: u32,
    tx_type: JsonTxType,
    destination: JsonDestinationPattern,
    signer: JsonSignerPattern,
    asset: JsonAssetPattern,
    amount_max: Option<String>,
    function_selector: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
enum JsonTxType {
    Transfer,
    ContractCall,
}

#[derive(Deserialize, Debug, Clone)]
enum JsonAssetPattern {
    Any,
    Exact(String),
}

#[derive(Deserialize, Debug, Clone)]
enum JsonDestinationPattern {
    Any,
    Group(String),
    Allowlist(String),
}

#[derive(Deserialize, Debug, Clone)]
enum JsonSignerPattern {
    Any,
    Exact(String),
    Group(String),
    Threshold { group: String, threshold: u8 },
}

impl From<JsonTxType> for CoreTxType {
    fn from(v: JsonTxType) -> Self {
        match v {
            JsonTxType::Transfer => CoreTxType::Transfer,
            JsonTxType::ContractCall => CoreTxType::ContractCall,
        }
    }
}

impl From<JsonDestinationPattern> for CoreDestinationPattern {
    fn from(v: JsonDestinationPattern) -> Self {
        match v {
            JsonDestinationPattern::Any => CoreDestinationPattern::Any,
            JsonDestinationPattern::Group(s) => CoreDestinationPattern::Group(s),
            JsonDestinationPattern::Allowlist(s) => CoreDestinationPattern::Allowlist(s),
        }
    }
}

impl From<JsonSignerPattern> for CoreSignerPattern {
    fn from(v: JsonSignerPattern) -> Self {
        match v {
            JsonSignerPattern::Any => CoreSignerPattern::Any,
            JsonSignerPattern::Exact(s) => {
                let mut addr = [0u8; 20];
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(s).expect("invalid hex in signer Exact address");
                addr.copy_from_slice(&bytes);
                CoreSignerPattern::Exact(addr)
            }
            JsonSignerPattern::Group(s) => CoreSignerPattern::Group(s),
            JsonSignerPattern::Threshold { group, threshold } => {
                CoreSignerPattern::Threshold { group, threshold }
            }
        }
    }
}

impl From<JsonAssetPattern> for CoreAssetPattern {
    fn from(v: JsonAssetPattern) -> Self {
        match v {
            JsonAssetPattern::Any => CoreAssetPattern::Any,
            JsonAssetPattern::Exact(s) => {
                let mut addr = [0u8; 20];
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let bytes = hex::decode(s).expect("invalid hex in asset Exact address");
                addr.copy_from_slice(&bytes);
                CoreAssetPattern::Exact(addr)
            }
        }
    }
}

impl From<JsonPolicyLine> for CorePolicyLine {
    fn from(val: JsonPolicyLine) -> Self {
        CorePolicyLine {
            id: val.id,
            tx_type: val.tx_type.into(),
            destination: val.destination.into(),
            signer: val.signer.into(),
            asset: val.asset.into(),
            amount_max: val.amount_max.map(|s| s.parse::<u128>().expect("invalid amount_max")),
            function_selector: val.function_selector.map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let mut arr = [0u8; 4];
                let bytes = hex::decode(s).expect("invalid function selector hex");
                arr.copy_from_slice(&bytes);
                arr
            }),
        }
    }
}

fn read_json_file<T: for<'de> Deserialize<'de>>(path: &str) -> Result<T> {
    let file = File::open(path).with_context(|| format!("open {}", path))?;
    let reader = BufReader::new(file);
    let v = serde_json::from_reader(reader).with_context(|| format!("parse json: {}", path))?;
    Ok(v)
}


fn sha256_hex_prefixed(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    format!("0x{}", hex::encode(digest))
}

fn root_hex_prefixed(root: [u8; 32]) -> String {
    format!("0x{}", hex::encode(root))
}

fn main() -> Result<()> {
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Args {
        #[clap(long)]
        policy: String,
        #[clap(long)]
        groups: String,
        #[clap(long)]
        allow: String,
    }

    let args = Args::parse();

    // Policy
    let json_policy: Vec<JsonPolicyLine> = read_json_file(&args.policy)?;
    let policy: Vec<CorePolicyLine> = json_policy.into_iter().map(|p| p.into()).collect();
    let mut leaves: Vec<[u8; 32]> = policy
        .iter()
        .map(|pl| hash_policy_line_for_merkle_tree(pl))
        .collect();
    // Match the prover: pad to next power-of-two by repeating the last leaf
    let n = leaves.len();
    let pow2 = n.next_power_of_two();
    if pow2 > n {
        let last = *leaves.last().expect("at least one leaf");
        leaves.extend(std::iter::repeat(last).take(pow2 - n));
    }
    let tree: MerkleTree<Sha256MerkleHasher> = MerkleTree::from_leaves(&leaves);
    let root = tree.root().context("empty policy: no root")?;

    // Groups
    let json_groups: HashMap<String, Vec<String>> = read_json_file(&args.groups)?;
    let mut groups_btree: BTreeMap<String, Vec<[u8; 20]>> = BTreeMap::new();
    for (k, v) in json_groups.into_iter() {
        let mut addrs: Vec<[u8; 20]> = Vec::with_capacity(v.len());
        for s in v {
            let s = s.strip_prefix("0x").unwrap_or(&s).to_string();
            let bytes = hex::decode(&s).with_context(|| format!("invalid hex address for key {}", k))?;
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            addrs.push(arr);
        }
        groups_btree.insert(k, addrs);
    }
    let (_canon_groups, groups_bytes) = zkguard_core::canonicalise_lists(groups_btree);

    // Allowlists
    let json_allow: HashMap<String, Vec<String>> = read_json_file(&args.allow)?;
    let mut allow_btree: BTreeMap<String, Vec<[u8; 20]>> = BTreeMap::new();
    for (k, v) in json_allow.into_iter() {
        let mut addrs: Vec<[u8; 20]> = Vec::with_capacity(v.len());
        for s in v {
            let s = s.strip_prefix("0x").unwrap_or(&s).to_string();
            let bytes = hex::decode(&s).with_context(|| format!("invalid hex address for key {}", k))?;
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            addrs.push(arr);
        }
        allow_btree.insert(k, addrs);
    }
    let (_canon_allow, allow_bytes) = zkguard_core::canonicalise_lists(allow_btree);

    // Output
    println!("POLICY_HASH={}", root_hex_prefixed(root));
    println!("GROUPS_HASH={}", sha256_hex_prefixed(&groups_bytes));
    println!("ALLOW_HASH={}", sha256_hex_prefixed(&allow_bytes));

    Ok(())
}
