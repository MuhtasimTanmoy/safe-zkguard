1. Create a proof
2. Deploy the ImageID.sol contract
  - forge create src/MyContract.sol:MyContract --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --broadcast
3. Set the .env variables for "Deployment"
4. Run the deploy module
  - forge script script/DeployModuleAndSafe.s.sol:DeploySafe --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --via-ir --broadcast -vvvvv
5. Set the .env variables for "Interaction"
6. Run the verify and execute
  - forge script script/VerifyAndExecFromProof.s.sol:VerifyAndExecFromProof --rpc-url <YOUR_RPC_URL> --private-key <YOUR_PRIVATE_KEY> --via-ir --broadcast -vvvvv