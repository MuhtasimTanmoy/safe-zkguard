# ZKGuard Safe Module On-chain Flow

## 1. Compile circuits and build prover

From the `risc0` directory, build the Rust code:

```bash
cargo build --release
```

## 2. Deploy the ImageID.sol contract

The `ImageID` contract stores the identifier for your zkVM application binary.

```bash
forge create src/ImageID.sol:ImageID --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --broadcast
```

Take note of the deployed `ImageID` contract address.

## 3. Set .env variables for Deployment

Create or update a `.env` file in the `risc0` directory. You can refer to the `.env.example` file for a full list of required variables. For deployment, you will need to set the required variables, ensuring you use the address of the `ImageID` contract you just deployed for the `IMAGE_ID_CONTRACT_ADDRESS` variable.

## 4. Deploy the ZKGuardSafeModule and Safe Wallet

This script deploys the `ZKGuardSafeModule` and a new Safe Wallet, then enables the module on the Safe.

```bash
forge script script/DeployModuleAndSafe.s.sol:DeploySafe --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --via-ir --broadcast -vvvvv
```

Take note of the deployed `ZKGuardSafeModule` address and the new `Safe` address from the script output.

## 5. Set .env variables for Interaction

Add the variables needed for interaction to your `.env` file. You can see a full list in `.env.example`. You will need to include the `MODULE_ADDRESS` and `SAFE_ADDRESS` from the previous step.

## 6. Create a proof and execute on-chain

Beforehand, in the general .env file, make sure to define the correct

SAFE_ADDRESS=<YOUR_SAFE_ADDRESS>

MODULE_ADDRESS=<ZK_SAFE_MODULE>

These should match the .env in the contract dir

Run one of the examples from the `dao_prover` to generate a proof and send the transaction for verification and execution on-chain.

Use the `--verify-onchain` flag to enable on-chain verification.

For example:

```bash
cargo run --release --example dao_prover -- --example contributor_payments --verify-onchain
```

This will:
1.  Generate a RISC Zero proof that the user action is valid according to the policy.
2.  Call the `verifyAndExec` function on the `ZKGuardSafeModule` contract.
3.  The module will verify the proof and, if valid, execute the transaction through the Safe Wallet.
