# Benchmarks
## OS Setup
Install ```python3``` and ```pip3```, in ubuntu that can be done by:
```bash
sudo apt-get install python3 python3-pip
```

Then install requirements:
```bash
pip3 install -r requirements.txt
```

### Solc
For tests with SC you need to have solc installed on your system:
```bash
https://docs.soliditylang.org/en/latest/installing-solidity.html
```

Then install the required version to compile contracts:
```bash
python3 -c 'from solcx import install_solc; install_solc("0.5.16")'
```

### Uniswap V2
To run Uniswap v2 deployment you need to update the submodule:
```bash
git submodule init
git submodule update
```

## Profiles setup
Use default ```profiles.json``` to add your own network.
You just need to set the RPC url and the path of a file containing the private key of the account that will be used to fund addresses for the test.
Keys under ```keys/``` are out of git scope, as well as ```private_profiles.json```, which uses the same format as ```profiles.json```

## Execute test
Minimal test to check everything runs:
 ```bash
 python3 bench.py --profile testnet --concurrency 1 --txs 1
  ```
  That's the shortcut for the same:
  ```bash
  python3 bench.py -p testnet -c 1 -t 1
  ```

  Replace *testnet* with the desired profile, and be sure the file with the private key exists and has funds enough.

  ### Bench options
  Mandatory options:
  - ```-p <string>``` To set the profile
  - ```-c <int>``` For concurrent thread count
  - ```-t <int>``` Number of transactions per thread
  
  Optional parameters (first one is the default):
- ```--confirmed``` or ```--no-confirmed``` Flag to enable or disable confirmed txs tests
- ```--unconfirmed``` or ```--no-unconfirmed``` Flag to enable or disable unconfirmed txs tests
- ```--erc20create``` or ```--no-erc20create``` Flag to enable or disable ERC20 Token creation tests
- ```--erc20txs``` or ```--no-erc20txs``` Flag to enable or disable ERC20 Token transfers, automatically disabled if ```--no-erc20create``` is set
- ```--uniswap``` or ```--no-uniswap``` Flag to enable or disable deployment of Uniswap v2 smart contracts
- ```--recover``` or ```--no-recover``` Attempt -or not- to recover remaining funds in created accounts -sent back the funded account-, may fail if there is not enough balance to pay fees.
- ```--no-race``` or ```--race``` Specific test that sends many transactions starting with future nonce, and the last transaction is the missing nonce that makes them all execute at once.

### Logging
Each execution is incrementally logged to ```bench.log``` file. You can find there all past results.
```bash
grep Results bench.log
```
You will also find on the log file all the transaction hashes for all the transactions sent.
