1. Deploy the Terranova smart contract to localterra (or testnet)
* cd contracts/terranova
* cargo build
* cargo run-script optimize
* cd ../../
* terrain deploy terranova --signer custom_tester_2 --network localterra --no-rebuild
* Get the contract address (terra10pyejy66429refv3g35g2t7am0was7ya7kz2a4)
* Testnet: terra1ax7tmszrrqpct4m9vsvgyuxswd3kvztfg8rryj

2. Build the Solidity contracts in Terranova core
* Get the unsigned transaction

3. Deploy the Solidity smart contract to Terranova EVM
* Use Python script in terranova-rpc/invoke-example.py

4. Try querying the value stored

5. Modify the value stored

6. Query the new value
