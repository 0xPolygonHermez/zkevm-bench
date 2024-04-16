from solcx import compile_files
from web3 import Web3
from threading import Thread
from hexbytes import HexBytes
from requests.exceptions import SSLError
import sys
import time
import logging
import argparse
import json


ap = argparse.ArgumentParser()
ap.add_argument('-p', '--profile', required=True, help="Profile to use")
ap.add_argument(
    "-c", "--concurrency", required=True, help="concurrent senders")
ap.add_argument("-t", "--txs", required=True, help="txs per sender")
ap.add_argument(
    "--race", action=argparse.BooleanOptionalAction,
    help="sequencer race", default=False
)
ap.add_argument(
    '--confirmed', action=argparse.BooleanOptionalAction, default=True)
ap.add_argument(
    '--unconfirmed', action=argparse.BooleanOptionalAction, default=True)
ap.add_argument(
    '--erc20create', action=argparse.BooleanOptionalAction, default=True)
ap.add_argument(
    '--erc20txs', action=argparse.BooleanOptionalAction, default=True)
ap.add_argument(
    '--uniswap', action=argparse.BooleanOptionalAction, default=True)
ap.add_argument(
    '--recover', action=argparse.BooleanOptionalAction, default=True)

args = vars(ap.parse_args())

f = open('profiles.json')
profiles = json.load(f).get('profiles')
f.close()
try:
    f = open('private_profiles.json')
except FileNotFoundError:
    pass
else:
    profiles |= json.load(f).get('profiles')
    f.close()

selected_profile = args['profile']
# RPC endpoint for the selected profile
node_url = profiles[selected_profile]['node_url']
# File with the private key
key_file = profiles[selected_profile]['key_file']
with open(key_file, 'r') as file:
    funded_key = file.read().strip()
# Connect to an Ethereum node (replace with your L2 node URL)
w3 = Web3(Web3.HTTPProvider(node_url))
l2_chainid = w3.eth.chain_id

# Address with balance enough to fund wallets:
account = w3.eth.account.from_key(str(funded_key))
funded_address = account.address

# Numbers of wallets to create, determines concurrency
num_senders = int(args['concurrency'])
# Number of txs to send per wallet, the total tx count per test will be:
#       num_senders * txs_per_sender
txs_per_sender = int(args['txs'])

do_race = args['race']
do_confirmed = args['confirmed']
do_unconfirmed = args['unconfirmed']
do_erc20create = args['erc20create']
do_erc20txs = do_erc20create and args['erc20txs']
do_uniswap = args['uniswap']
do_recover = args['recover']

# Eth amount to send in each tx, so on the funded_address you need to have:
#       eth_amount * num_senders * txs_per_sender * 2
eth_amount = 0.0001
# Solidity contract file
contract_file = "ERC20Token.sol"
contract_create_gas = 1125589
token_transfer_gas = 60000

# Internal params
log_file = "bench.log"
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(
    filename=log_file, format='%(asctime)s %(levelname)s %(message)s',
    filemode='a')
log_tx_per_line = 10

gas_price = w3.eth.gas_price
while gas_price*21000 > w3.to_wei(eth_amount, 'ether'):
    eth_amount = eth_amount * 1.10


def create_wallets(n):
    sender_wallets = [w3.eth.account.create() for _ in range(n)]
    receiver_wallets = [w3.eth.account.create() for _ in range(n)]

    return (sender_wallets, receiver_wallets)


def wrapped_send_raw_transaction(w, tx, prvkey, hex=True, retries=5):
    signed_transaction = w.eth.account.sign_transaction(tx, prvkey)
    try:
        tx_hash = w.eth.send_raw_transaction(signed_transaction.rawTransaction)
    except SSLError:
        if retries:
            sleep_time = (30 - retries*retries)
            say("Retrying send_raw_transaction in "
                f"{sleep_time}s ({retries} left)")
            time.sleep(sleep_time)
            return wrapped_send_raw_transaction(
                w, tx, prvkey, hex=hex, retries=retries-1
            )
        else:
            raise
    except ValueError as e:
        message = (e.args[0] and e.args[0].get('message'))
        if message == 'effective gas price: gas price too low':
            tx['gasPrice'] = int(tx['gasPrice'] * 1.5)
            say(f"Adjusting gasPrice to {tx['gasPrice']}")
            return wrapped_send_raw_transaction(
                w, tx, prvkey, hex=hex, retries=retries-1
            )
        else:
            raise
    else:
        if hex:
            return tx_hash.hex()
        else:
            return tx_hash


def send_transaction(
    w, sender_address, sender_key, receiver_address, eth_amount,
    gas_price=None, nonce=None, wait=True, gas_from_amount=False,
    check_balance=True, count=1, print_hash=False, all_balance=False,
    data=None, gas=21000
):
    tx_hashes = []

    if nonce is None:
        nonce = w.eth.get_transaction_count(sender_address)

    if gas_price is None:
        gas_price = w.eth.gas_price
    if all_balance:
        amount = w.eth.get_balance(sender_address)
    else:
        amount = w.to_wei(eth_amount, 'ether')

    if gas_from_amount:
        original_amount = amount
        amount = amount - gas * gas_price

    if amount < 0 and all_balance:
        say(
            f"WARN: amount is negative. original_amount:{original_amount}, "
            f"amount:{amount}, gas*gas_price:{gas*gas_price}"
        )
        return tx_hashes

    elif amount < 0:
        say(
            f"ERROR: amount is negative. original_amount:{original_amount}, "
            f"amount:{amount}, gas*gas_price:{gas*gas_price}"
        )
        return tx_hashes
    elif amount == 0 and receiver_address is not None:
        say("WARN: amount for tx is ZERO, aborting")
        return tx_hashes

    if check_balance:
        balance = w.eth.get_balance(sender_address)
        assert balance >= amount * count

    for i in range(count):
        transaction = {
            'to': receiver_address,
            'value': amount,
            'gas': gas,
            'gasPrice': gas_price,
            'nonce': nonce + i,
            # 'chainId': l2_chainid,
        }
        if data:
            transaction['data'] = data

        # signed_transaction = w.eth.account.sign_transaction(
        #     transaction, sender_key
        # )
        tx_hash = HexBytes('')
        try:
            tx_hash = wrapped_send_raw_transaction(
                w, transaction, sender_key, hex=False
            )
            # tx_hash = w.eth.send_raw_transaction(
            #     signed_transaction.rawTransaction)
        except ValueError as e:
            say(f"Error sending {amount} from {sender_address} to "
                f"{receiver_address} (txhash: {tx_hash.hex()}): {e}")
        except Exception:
            raise
        else:
            tx_hashes.append(tx_hash.hex())
            if print_hash:
                say(tx_hash.hex())

    if wait:
        # print(F"WAITING FOR: {tx_hashes[-1]}")
        w.eth.wait_for_transaction_receipt(
            tx_hashes[-1], timeout=180, poll_latency=0.2)

        # for tx_hash in tx_hashes:
        #     print(F"WAITING FOR: {tx_hash}")
        #     w.eth.wait_for_transaction_receipt(
        #         tx_hash, timeout=180, poll_latency=0.2)

    return tx_hashes


def token_transfer(
    w, token_contract, token_abi, src, src_prvkey, dst, wei_amount, gas_price,
    nonce
):
    c = w.eth.contract(address=token_contract, abi=token_abi)

    tx = c.functions.transfer(dst, wei_amount).build_transaction({
        'nonce': nonce,
        'gas': token_transfer_gas,
        'gasPrice': gas_price,
        'chainId': l2_chainid,
    })

    # signed_tx = w.eth.account.sign_transaction(tx, src_prvkey)
    # tx_hash = w.eth.send_raw_transaction(signed_tx.rawTransaction).hex()
    tx_hash = wrapped_send_raw_transaction(w, tx, src_prvkey)

    _ = w.eth.wait_for_transaction_receipt(
        tx_hash, timeout=120, poll_latency=0.2
    )
    return tx_hash


class TxSender(Thread):
    def __init__(self, args, kwargs):
        Thread.__init__(self)
        self.args = args
        self.kwargs = kwargs
        self.tx_hashes = None

    def run(self):
        self.tx_hashes = send_transaction(*self.args, **self.kwargs)


class MultiTxSender(Thread):
    def __init__(self, args, kwargs, multidata):
        Thread.__init__(self)
        self.args = args
        self.kwargs = kwargs
        self.tx_hashes = []
        self.multidata = multidata

    def run(self):
        gas_price = w3.eth.gas_price
        self.kwargs['gas_price'] = gas_price
        for data in self.multidata:
            tx_hashes = send_transaction(
                *self.args, **{**self.kwargs, 'data': data}
            )
            self.kwargs['nonce'] += txs_per_sender
            self.tx_hashes.extend(tx_hashes)


def fund_wallets_in_parallel(wallets, eth_amount, v=False):
    threads = []
    nonce = w3.eth.get_transaction_count(funded_address, 'pending')
    say(
        f"Funding {len(wallets)} wallets with {eth_amount:.6f}ETH each, "
        f"using funds from {funded_address}..."
    )
    for wallet in wallets:
        thread = TxSender(
            args=(
                w3, funded_address, funded_key, wallet.address, eth_amount
            ),
            kwargs={'wait': True, 'check_balance': False, 'nonce': nonce}
        )

        threads.append(thread)
        thread.start()
        nonce = nonce + 1

    tx_hashes = []
    for thread in threads:
        thread.join()
        tx_hashes.extend(thread.tx_hashes)

    say("Fund Wallets Tx Hashes:", output=False)
    for x in range(0, len(tx_hashes), log_tx_per_line):
        say(tx_hashes[x:x+log_tx_per_line], output=False)


def send_transactions_in_parallel(wait, nonce, count=txs_per_sender):
    threads = []
    gas_price = w3.eth.gas_price

    for i in range(num_senders):
        thread = TxSender(
            args=(
                w3, sender_wallets[i].address, sender_wallets[i].key.hex(),
                receiver_wallets[i].address, eth_amount
            ),
            kwargs={
                'wait': wait, 'gas_price': gas_price, 'print_hash': False,
                'gas_from_amount': True, 'check_balance': False,
                'count': count, 'nonce': nonce
            }
        )
        threads.append(thread)
        thread.start()

    tx_hashes = []
    for thread in threads:
        thread.join()
        if thread.tx_hashes:
            tx_hashes.extend(thread.tx_hashes)

    say("Bench Send Tx Hashes:", output=False)
    for x in range(0, len(tx_hashes), log_tx_per_line):
        say(tx_hashes[x:x+log_tx_per_line], output=False)


def recover_funds_in_parallel():
    threads = []
    for i in range(num_senders):
        thread = TxSender(
            args=(
                w3, receiver_wallets[i].address,
                receiver_wallets[i].key.hex(), funded_address, 0
            ),
            kwargs={
                'wait': True, 'print_hash': False, 'all_balance': True,
                'gas_from_amount': True, 'check_balance': True
            }
        )

        threads.append(thread)
        thread.start()

    tx_hashes = []
    for thread in threads:
        thread.join()
        tx_hashes.extend(thread.tx_hashes)

    say("Recover Funds Tx Hashes:", output=False)
    for x in range(0, len(tx_hashes), log_tx_per_line):
        say(tx_hashes[x:x+log_tx_per_line], output=False)


def compile_contract():
    # Compile the contract from the file
    compiled_contracts = compile_files(
        [contract_file], evm_version='paris', output_values=["bin", "abi"]
    )

    # Get the bytecode of the ERC20Token contract
    bytecode = compiled_contracts["ERC20Token.sol:ERC20Token"]["bin"]
    abi = compiled_contracts["ERC20Token.sol:ERC20Token"]["abi"]

    return (abi, bytecode)


def compile_uniswap_v2():
    contracts = [
        "v2-core/contracts/UniswapV2Pair.sol",
        "v2-core/contracts/UniswapV2Factory.sol",
        "v2-core/contracts/UniswapV2ERC20.sol",
    ]
    compiled_contracts = compile_files(
        contracts, output_values=["bin"], solc_version="0.5.16"
    )
    bytecodes = []
    for cc in compiled_contracts.keys():
        if compiled_contracts[cc].get('bin'):
            bytecodes.append(compiled_contracts[cc]['bin'])

    return bytecodes


class ContractDeployer(Thread):
    def __init__(
            self, account_address, private_key, nonce, count, abi, bytecode,
    ):
        Thread.__init__(self)
        self.account_address = account_address
        self.nonce = nonce
        self.count = count
        self.abi = abi
        self.bytecode = bytecode
        self.private_key = private_key
        self.tx_hashes = []
        self.contract_addresses = []

    def run(self):
        ERC20 = w3.eth.contract(abi=self.abi, bytecode=self.bytecode)
        gas_price = int(w3.eth.gas_price * 1.25)
        for i in range(self.count):
            transaction = ERC20.constructor(500).build_transaction(
                {
                    'from': self.account_address,
                    'nonce': self.nonce + i,
                    'gasPrice': gas_price,
                    'gas': contract_create_gas,
                    'chainId': l2_chainid
                }
            )

            # Sign the transaction
            # signed_transaction = w3.eth.account.sign_transaction(
            #     transaction, self.private_key)

            # Send the signed transaction
            tx_hash = wrapped_send_raw_transaction(
                w3, transaction, self.private_key, hex=False)
            # tx_hash = w3.eth.send_raw_transaction(
            #     signed_transaction.rawTransaction)

            self.tx_hashes.append(tx_hash.hex())

            # Wait for the transaction to be mined
            say(f"Waiting for erc20 create tx {tx_hash.hex()}")
            transaction_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

            # Get the deployed contract address
            self.contract_addresses.append(
                transaction_receipt['contractAddress'])


def deploy_contracts_in_paralel(abi, bytecode, nonce):
    threads = []
    for i in range(num_senders):
        thread = ContractDeployer(
            sender_wallets[i].address, sender_wallets[i].key.hex(), nonce,
            txs_per_sender, abi, bytecode)

        threads.append(thread)
        thread.start()

    contracts = []
    contract_addresses = []
    tx_hashes = []
    for thread in threads:
        thread.join()
        if thread.tx_hashes:
            contract_addresses.append(thread.contract_addresses)
            contracts.append(
                (
                    thread.account_address, thread.private_key,
                    thread.contract_addresses
                )
            )
            tx_hashes.extend(thread.tx_hashes)

    say("SC Create Tx Hashes:", output=False)
    for x in range(0, len(tx_hashes), log_tx_per_line):
        say(tx_hashes[x:x+log_tx_per_line], output=False)

    say("SC Addresses:", output=False)
    for x in range(0, len(contracts), log_tx_per_line):
        say(contract_addresses[x:x+log_tx_per_line], output=False)

    return contracts


class TokenTransfer(Thread):
    def __init__(
            self, sc, token_abi, src, prvkey, funded_address, wei_amount,
            gas_price, nonce
    ):
        Thread.__init__(self)
        self.sc = sc
        self.token_abi = token_abi
        self.src = src
        self.prvkey = prvkey
        self.funded_address = funded_address
        self.wei_amount = wei_amount
        self.gas_price = gas_price
        self.nonce = nonce

    def run(self):
        token_transfer(
            w3, self.sc, self.token_abi, self.src, self.prvkey,
            self.funded_address, self.wei_amount, self.gas_price, self.nonce
        )


def transfer_tokens_in_paralel(contracts):
    threads = []
    wei_amount = w3.to_wei(eth_amount, 'ether')
    gas_price = w3.eth.gas_price
    for contract in contracts:
        src = contract[0]
        prvkey = contract[1]
        deployed_contracts = contract[2]
        nonce = w3.eth.get_transaction_count(src)
        for i, sc in enumerate(deployed_contracts):
            thread = TokenTransfer(
                sc, token_abi, src, prvkey, funded_address, wei_amount,
                gas_price, nonce+i)

            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()


def deploy_uniswap_in_paralel(nonce):
    uniswap_scs = compile_uniswap_v2()
    threads = []
    gas_price = w3.eth.gas_price

    for i in range(num_senders):
        thread = MultiTxSender(
            args=(
                w3, sender_wallets[i].address, sender_wallets[i].key.hex(),
                None, 0
            ),
            kwargs={
                'wait': True, 'gas_price': gas_price, 'print_hash': False,
                'gas_from_amount': False, 'check_balance': False,
                'nonce': nonce, 'count': txs_per_sender,
                'gas': contract_create_gas
            },
            multidata=uniswap_scs
        )
        threads.append(thread)
        thread.start()

    tx_hashes = []
    for thread in threads:
        thread.join()
        if thread.tx_hashes:
            tx_hashes.extend(thread.tx_hashes)

    say("Bench Uniswap Tx Hashes:", output=False)
    for x in range(0, len(tx_hashes), log_tx_per_line):
        say(tx_hashes[x:x+log_tx_per_line], output=False)


def say(msg, to_log=True, output=True):
    if to_log:
        logger.info(msg)
    if output:
        print(msg)


initial_balance = w3.eth.get_balance(funded_address)
bench_results = [
    f"{node_url}:{w3.client_version}",
    f"senders:{num_senders}",
    f"tx_per_sender:{txs_per_sender}"
]

say(f"** Starting benchmark against {node_url} ({w3.client_version}) | "
    f"Profile: {selected_profile} | ChainId: {l2_chainid} | "
    f"Funded address: {funded_address} | Balance: {initial_balance} wei |"
    f"{num_senders} senders, {txs_per_sender} txs per sender")
say(f"Logging everything to: {log_file}")

# CREATE AND FUND WALLETS
(sender_wallets, receiver_wallets) = create_wallets(num_senders)

total_eth_amount = 0

if do_race:
    total_eth_amount += txs_per_sender*eth_amount
if do_confirmed:
    total_eth_amount += txs_per_sender*eth_amount
if do_unconfirmed:
    total_eth_amount += txs_per_sender*eth_amount
if do_erc20create:
    total_eth_amount += txs_per_sender*float(
        w3.from_wei(contract_create_gas*gas_price*1.25, 'ether')
    )
if do_erc20txs:
    total_eth_amount += txs_per_sender*float(
        w3.from_wei(token_transfer_gas*gas_price*1.25, 'ether')
    )
if do_uniswap:
    total_eth_amount += 6*txs_per_sender*float(
        w3.from_wei(contract_create_gas*gas_price*1.10, 'ether')
    )
start_time = time.time()
gas_price = w3.eth.gas_price
fund_wallets_in_parallel(sender_wallets, total_eth_amount*5)
end_time = time.time()
total_time = end_time - start_time
say(f"Time to fund {num_senders} wallets: {total_time:.2f} seconds"
    f", {(num_senders/total_time):.2f} TPS | "
    f"For each tx: Check gas price + Wait confirmation")
bench_results.append(f"fund:{(num_senders/total_time):.2f}")

global_nonce_per_sender = 0

# SEQUENCER RACE
if do_race:
    assert (txs_per_sender > 2)
    start_time = time.time()
    # Send from nonce 1 to txs-per-sender-1
    send_transactions_in_parallel(
        wait=False, nonce=1, count=(txs_per_sender-1))
    # for i in range(num_senders):
    #     send_transaction(
    #         w3,
    #         sender_address=sender_wallets[i].address,
    #         sender_key=sender_wallets[i].key.hex(),
    #         receiver_address=receiver_wallets[i].address,
    #         eth_amount=eth_amount,
    #         nonce=1,
    #         count=(txs_per_sender-1),
    #         wait=False,
    #         gas_from_amount=True
    #     )
    # Send nonce 0 to launch all prev txs
    send_transactions_in_parallel(wait=False, nonce=0, count=1)
    # for i in range(num_senders):
    #     send_transaction(
    #         w3,
    #         sender_address=sender_wallets[i].address,
    #         sender_key=sender_wallets[i].key.hex(),
    #         receiver_address=receiver_wallets[i].address,
    #         eth_amount=eth_amount,
    #         nonce=0,
    #         count=1,
    #         wait=False,
    #         gas_from_amount=True
    #     )

    confirmed = {i: False for i in range(num_senders)}
    while (not all(confirmed[i] for i in range(num_senders))):
        for i in range(num_senders):
            if confirmed[i]:
                continue
            else:
                nonce = w3.eth.get_transaction_count(sender_wallets[i].address)
                if nonce == txs_per_sender:
                    say(f"Confirming sender num {i}")
                    confirmed[i] = True

    end_time = time.time()
    total_time = end_time - start_time
    say(f"Time to send {txs_per_sender} txs for {num_senders} senders to "
        f"{num_senders} receivers (total of {txs_per_sender*num_senders} txs):"
        f" {total_time:.2f} seconds | "
        f"Avg speed: {((num_senders*txs_per_sender)/total_time):.2f} TPS | "
        f"Race Sequencer confirmed txs")
    sys.exit()

# CONFIRMED TXS
if do_confirmed:
    start_time = time.time()
    send_transactions_in_parallel(wait=True, nonce=global_nonce_per_sender)
    end_time = time.time()
    total_time = end_time - start_time
    average_time = total_time / (num_senders*txs_per_sender)
    say(f"Time to send {txs_per_sender} txs for {num_senders} senders to "
        f"{num_senders} receivers (total of {txs_per_sender*num_senders} txs):"
        f" {total_time:.2f} seconds | "
        f"Avg speed: {((num_senders*txs_per_sender)/total_time):.2f} TPS | "
        f"Confirmed txs, no balance check, no gas price check")
    bench_results.append(
        f"confirmed:{((num_senders*txs_per_sender)/total_time):.2f}")

    global_nonce_per_sender += txs_per_sender
    confirmed_total_time = total_time

# UNCONFIRMED TXS
if do_unconfirmed:
    start_time = time.time()
    send_transactions_in_parallel(wait=False, nonce=global_nonce_per_sender)
    end_time = time.time()
    total_time = end_time - start_time
    average_time = total_time / (num_senders*txs_per_sender)
    say(f"Time to send {txs_per_sender} txs for {num_senders} senders to "
        f"{num_senders} receivers (total of {txs_per_sender*num_senders} txs):"
        f" {total_time:.2f} seconds | "
        f"Avg speed: {((num_senders*txs_per_sender)/total_time):.2f} TPS | "
        f"Unconfirmed txs, no balance check, no gas price check")
    bench_results.append(
        f"unconfirmed:{((num_senders*txs_per_sender)/total_time):.2f}")

    global_nonce_per_sender += txs_per_sender
    if not do_confirmed:
        confirmed_total_time = total_time * 3

    # say(
    #     f"Waiting {int(confirmed_total_time-total_time)}s "
    #     "to allow unconfirmed txs to be processed"
    # )
    # time.sleep(int(confirmed_total_time-total_time))

# CREATE ERC20 TOKENS
if do_erc20create:
    (token_abi, bytecode) = compile_contract()
    start_time = time.time()
    contracts = deploy_contracts_in_paralel(
        token_abi, bytecode, nonce=global_nonce_per_sender)
    end_time = time.time()
    total_time = end_time - start_time
    say(f"Time to create {txs_per_sender} tokens for {num_senders} senders "
        f"(total of {txs_per_sender*num_senders} tokens): {total_time:.2f} "
        f"seconds | Avg speed: {((num_senders*txs_per_sender)/total_time):.2f}"
        f" TPS | Each SC creation is confirmed")
    bench_results.append(
        f"erc20create:{((num_senders*txs_per_sender)/total_time):.2f}")
    global_nonce_per_sender += txs_per_sender

# ERC20 TOKEN TRANSFER
if do_erc20txs:
    start_time = time.time()
    transfer_tokens_in_paralel(contracts)
    end_time = time.time()
    total_time = end_time - start_time
    say(f"Time to send {txs_per_sender} token txs for {num_senders} senders "
        f"(total of {txs_per_sender*num_senders} token txs): {total_time:.2f} "
        f"seconds | Avg speed: {((num_senders*txs_per_sender)/total_time):.2f}"
        f" TPS | Each Token Transfer is confirmed")
    bench_results.append(
        f"erc20tx:{((num_senders*txs_per_sender)/total_time):.2f}")
    global_nonce_per_sender += txs_per_sender

# UNISWAP V2 DEPLOYMENT
if do_uniswap:
    start_time = time.time()
    deploy_uniswap_in_paralel(nonce=global_nonce_per_sender)
    end_time = time.time()
    total_time = end_time - start_time
    say(f"Time to deploy {txs_per_sender*6} uniswap contracts for "
        f"{num_senders} senders (total of {txs_per_sender*num_senders*6} sc "
        f"create): {total_time:.2f} seconds | Avg speed: "
        f"{((num_senders*txs_per_sender*6)/total_time):.2f}"
        f" TPS | Each SC Create is confirmed")
    bench_results.append(
        f"uniswap:{((num_senders*txs_per_sender*6)/total_time):.2f}")
    global_nonce_per_sender += txs_per_sender*6

# RECOVER FUNDS
if do_recover:
    start_time = time.time()
    recover_funds_in_parallel()
    end_time = time.time()
    total_time = end_time - start_time
    average_time = total_time / (num_senders*txs_per_sender)
    say(f"Time to send {txs_per_sender} txs for {num_senders} senders back to "
        f"main account {funded_address}: "
        f"{total_time:.2f} seconds | "
        f"Avg speed: {((num_senders*txs_per_sender)/total_time):.2f} TPS | "
        f"Confirmed txs, +nonce check, +balance check, +gas price check")
    # bench_results.append(
    #     f"recover:{((num_senders*txs_per_sender)/total_time):.2f}")

final_balance = w3.eth.get_balance(funded_address)
say(f"Initial:{initial_balance} Final:{final_balance}")
eth_cost = float(w3.from_wei(initial_balance-final_balance, 'ether'))
bench_results.insert(1, f"eth_cost:{eth_cost:.5f}")
bench_results.insert(1, f"profile:{selected_profile}")

say(f"Results: {bench_results}")
say("** Benchmark done | "
    f"Logged everything to: {log_file}")
