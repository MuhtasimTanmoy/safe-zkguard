# Safe-ZKGuard: ZKGuard implementation using Safe{Wallet}

This directory contains a `Safe{Wallet}`-based implementation of the ZKGuard policy engine. For more information on ZKGuard, please visit the [ZKGuard](https://github.com/ziemen4/zkguard) repository.

## Risc0 Implementation

We implement ZKGuard using [Risc0](https://risczero.com/), which yields high expressivity but more proving complexity and latency.
It leverages a Zero-Knowledge Virtual Machine (zkVM) to prove policy compliance by executing a standard Rust program in a verifiable manner. This approach provides significant flexibility, allowing for complex, expressive policies to be written in a general-purpose language without the need to design low-level arithmetic circuits.

**Host Program** (`examples/prover.rs`): This is an untrusted program that runs on a standard machine. Its primary role is to prepare all the necessary inputs for the proof. This includes loading the user's action from command-line arguments, finding the specific policy rule that allows it, and fetching any required context like address groups and allow-lists. It then invokes the guest program within the zkVM.

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

## End-to-End Guide: Deployment and Execution

This guide will walk you through deploying the smart contracts and using the prover to generate a proof and execute a transaction on-chain.

### Prerequisites

*   Rust, configured with the toolchain specified in `rust-toolchain.toml`. If you have `rustup` installed, it will automatically use the correct version when you are in this directory.
*   Foundry for Solidity development and deployment.

### Step 1: Compile Circuits and Build Prover

From this `risc0` directory, build the Rust code. This compiles the guest program (the "circuit") and should create a new `ImageID.sol` contract under the `contracts/src` directory.

```bash
cargo build --release
```

### Step 2: Deploy the `ImageID.sol` Contract

The `ImageID` contract stores the unique identifier for your zkVM guest program. If the guest code changes, the Image ID will change, and a new deployment will be required.

```bash
forge create contracts/src/ImageID.sol:ImageID --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --broadcast
```

Take note of the deployed `ImageID` contract address.

### Step 3: Set `.env` Variables for Deployment

Create or update a `.env` file in the `contracts` directory. You can refer to the `.env.template` file for a full list of required variables. Ensure you set `RISC0_IMAGE_ID` to the address of the `ImageID` contract you just deployed.

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
    --policy-file risc0/examples-v2/policy.json \
    --groups-file risc0/examples-v2/groups.json \
    --allowlists-file risc0/examples-v2/allowlists.json \
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
