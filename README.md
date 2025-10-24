# Safe-ZKGuard: ZKGuard implementation using Safe{Wallet}

This directory contains a `Safe{Wallet}`-based implementation of the ZKGuard policy engine via a [Safe Module](https://docs.safe.global/advanced/smart-account-modules). For more information on ZKGuard, please visit the [ZKGuard](https://github.com/ziemen4/zkguard) repository.

## Risc0 Implementation

We implement ZKGuard using [Risc0](https://risczero.com/), which yields high expressivity but more proving complexity and latency.
It leverages a Zero-Knowledge Virtual Machine (zkVM) to prove policy compliance by executing a standard Rust program in a verifiable manner. This approach provides significant flexibility, allowing for complex, expressive policies to be written in a general-purpose language without the need to design low-level arithmetic circuits.

**Host Program** (`examples/prover.rs` or `src/main.rs`): This is an untrusted program that runs on a standard machine. Its primary role is to prepare all the necessary inputs for the proof. The `examples/prover.rs` also includes loading the user's action from command-line arguments, finding the specific policy rule that allows it, and fetching any required context like address groups and allow-lists. It then invokes the guest program within the zkVM.

**Guest Program** (`methods/guest/src/bin/zkguard_policy.rs`): This is the trusted program whose execution is proven. It runs inside the Risc0 zkVM. The guest receives the inputs from the host and performs the complete two-part verification:

1.  **Proof of Membership**: It verifies that the provided `PolicyLine` and `MerklePath` correctly compute to the trusted `Merkle Root`. This cryptographically proves that the rule is an authentic part of the established policy set.
   
2.  **Proof of Compliance**: It evaluates the `UserAction` against the now-authenticated `PolicyLine`. This involves checking the transaction type, destination, asset, amount, function selectors, and verifying the nonce.

If both steps succeed, the zkVM generates a ZKP (`Receipt`) which contains a `Journal`. The guest commits the public hashes of the inputs (`CallHash`, `PolicyMerkleRoot`, `GroupsHash`, `AllowHash`) to this journal, making them available for public verification.

## Policy Structure

Policies are defined using Rust structs and enums located in the `zkguard_core` crate and configured via JSON files in `examples/`.

*   `PolicyLine`: The core struct defining a single rule.
*   `TxType`: `Transfer` or `ContractCall`.
*   `DestinationPattern`:
    *   `Any`
    *   `Group(String)`: Destination must be in a named group (e.g., "TeamWallets").
    *   `Allowlist(String)`: Destination must be in a named list (e.g., "ApprovedDEXs").
*   `SignerPattern`:
    *   `Any`: Any valid signature.
    *   `Exact([u8; 20])`: A specific signer address.
    *   `Group(String)`: The signer must belong to a named group.
    *   `Threshold { group: String, threshold: u8 }`: A minimum number of signers from a named group must have signed.
*   `AssetPattern`: `Any` or `Exact([u8; 20])` (a specific token address).

## Running the Main Prover

We outline a simple application for generating a proof in `src/main.rs`. You can run it directly to create a proof for a given user action against a policy. The `examples` directory provides a complete end-to-end test case, including pre-defined policy, group, and allowlist files that are compatible with the on-chain contracts.

To run the main prover, use the following command from the `risc0` directory. By default, dev mode skips proof generation, set `RISC0_DEV_MODE=0` to generate a real proof.

```bash
cargo run --release
```

## End-to-End Guide: Deployment and Execution

This guide will walk you through deploying the smart contracts and using the prover to generate a proof and execute a transaction on-chain.

### Prerequisites

- Rust/Cargo ≥ 1.85.0 (Rust 2024 edition).

  Quick check (both must be ≥ 1.85.0):

  ```bash
  rustc -V   # must be >= 1.85.0
  cargo -V   # must be >= 1.85.0
  ```

- Pinned toolchain: this repo pins the RISC Zero workspace to Rust 1.86.0 via `risc0/rust‑toolchain.toml`. With `rustup`, the correct toolchain is used automatically when building under `risc0/`.

- Install RISC Zero tools (required for local proving):

  ```bash
  # install rzup (RISC Zero toolchain manager)
  curl -L https://risczero.com/install | bash
  # install the latest RISC Zero toolchain (includes the r0vm server)
  rzup install
  # verify the r0vm server is available
  r0vm --version
  ```

  The `r0vm` version must match the `risc0-zkvm` crate version used by this repo (e.g., 3.x). If they don’t match, update your toolchain with `rzup install` and ensure your shell PATH includes the directory set by the installer.

- Foundry for Solidity development and deployment.

### Quickstart (Environment)

Before building or running, create a local `.env` for the RISC Zero workspace and default to dev mode (to avoid proof generation which requires high CPU and RAM usage):

```bash
cp risc0/.env.example risc0/.env
# RISC0_DEV_MODE=1  # dev mode ⇒ no actual proof generated
```

When you’re ready to generate real proofs, set `RISC0_DEV_MODE=0` in `risc0/.env`. Alternatively, you can also use [Bonsai](https://dev.risczero.com/api/generating-proofs/remote-proving), though this will leak your policy.

### Step 1: Compile Circuits and Build Prover

From this `risc0` directory, build the Rust code. This compiles the guest program (the "circuit") and should create a new `ImageID.sol` contract under the `contracts/src` directory.****

```bash
cargo build --release
```

### Step 2: Deploy the `ImageID.sol` Contract

The `ImageID` contract stores the unique identifier for your zkVM guest program. If the guest code changes, the Image ID will change, and a new deployment will be required.

```bash
cd contracts

forge create src/ImageID.sol:ImageID --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --broadcast
```

Take note of the deployed `ImageID` contract address.

### Step 3: Configure `contracts/.env`

Create a local env file for contract deployment and configuration:

```bash
cd contracts
cp -n .env.template .env
```

Now fill in the variables in `contracts/.env`:

- `RISC0_VERIFIER` (or Router): Address of the RISC Zero on-chain verifier. Prefer the Router if available on your target chain; otherwise use the Groth16 verifier for your proof system. See [Verifier Contracts](https://dev.risczero.com/api/blockchain-integration/contracts/verifier)
- `RISC0_IMAGE_ID`: Address of the `ImageID` contract you deployed in Step 2.
- `NICK_SEED`: A 32-byte hex value (0x-prefixed). Acts as a non-secret seed/salt used for deterministic operations in scripts.
- `POLICY_HASH`, `GROUPS_HASH`, `ALLOW_HASH`: Hashes of your policy, groups, and allowlists used by the verifier. You can ompute them via the helper tool below.
- `SAFE_SINGLETON`, `SAFE_PROXY_FACTORY`, `SAFE_FALLBACK_HANDLER`: Safe{Wallet} canonical addresses for your network. See [Safe deployments](https://github.com/safe-global/safe-deployments)
- `SAFE_SALT_NONCE`: Arbitrary nonce for deterministic Safe address derivation;
- 
Compute the hashes and paste them into `contracts/.env`:

```bash
cargo run --release --bin compute-hashes -- \
  --policy  examples/policy.json \
  --groups  examples/groups.json \
  --allow   examples/allowlists.json
# prints:
# POLICY_HASH=0x...
# GROUPS_HASH=0x...
# ALLOW_HASH=0x...
```

### Step 4: Deploy the ZKGuardSafeModule and Safe Wallet

This script deploys the `ZKGuardSafeModule` and a new Gnosis Safe, then enables the module on the Safe.

```bash
forge script script/DeployModuleAndSafe.s.sol:DeploySafe --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --via-ir --broadcast -vvvvv
```

Take note of the deployed `ZKGuardSafeModule` address and the new `Safe` address from the script output.

### Step 5: Set `.env` Variables for Prover Interaction

Create or update a `.env` file in this `risc0` directory (this is separate from the one in `contracts`). Refer to `.env.example` for the required variables. You must include the `MODULE_ADDRESS` and `SAFE_ADDRESS` that were deployed in the previous step.

### Step 6: Create a Proof and Execute On-Chain

Run the `prover` example to generate a proof and send the transaction for verification and execution. The command requires you to specify the policy files, the rule ID, and the full details of the user action.

```bash
cargo run --release --example prover -- \
    --policy-file risc0/examples/policy.json \
    --groups-file risc0/examples/groups.json \
    --allowlists-file risc0/examples/allowlists.json \
    --rule-id <RULE_ID> \
    --to <TO_ADDRESS> \
    --value <VALUE_IN_WEI> \
    --data <HEX_CALLDATA> \
    --private-key <SIGNER_PRIVATE_KEY> \
    --nonce <SAFE_NONCE> \
    --verify-onchain
```

This command will:
1.  Generate a RISC Zero proof that the user action is valid according to the specified policy rule.
2.  Call the `verifyAndExec` function on the deployed `ZKGuardSafeModule` contract.
3.  The module will verify the proof and, if valid, execute the transaction through the Safe.
