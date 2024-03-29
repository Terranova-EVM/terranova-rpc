import rlp
from terra_sdk.client.lcd.api.tx import CreateTxOptions
from terra_sdk.client.localterra import LocalTerra
from terra_sdk.client.lcd import LCDClient
from terra_sdk.key.mnemonic import MnemonicKey
from terra_sdk.core.wasm import MsgStoreCode, MsgInstantiateContract, MsgExecuteContract
from terra_sdk.core.fee import Fee
from terra_sdk.core.coins import Coins
from sha3 import keccak_256
import requests
from time import sleep
import asyncio

terranova_contract = "terra128vhhjmu3vj0st3szrwnxh4m6h8rpq3hrftnlh"
mnemonic = "remain yard rebuild eternal okay ginger deputy paper scatter square meadow manage filter present lend off shoe moral impact defy analyst present amateur enough"

caller_evm_address = "B34e2213751c5d8e9a31355fcA6F1B4FA5bB6bE1"
receiver_evm_address = "2e36b2970ab7A4C955eADD836585c21A087Ab904"
contract_addresses = {
    "NOVA_token_address": "c8707e6a4820e5f7d9b9f7659e59dc9dfc8dc02d",
    "uniswap_factory": "72c41550b6c05c4f8e5494743ca7cab7d5f87afb",
    "uniswap_exchange": "01434c2bb38d9806b986c2e7d313e11c81340976",
    "NOVA_exchange_address": "47e0a3ddd614e28670da25b414afad2751741725"
}

tx_chunk_size = 800 #bytes

class NoChainTrx(rlp.Serializable):
    fields = (
        ('nonce', rlp.codec.big_endian_int),
        ('gasPrice', rlp.codec.big_endian_int),
        ('gasLimit', rlp.codec.big_endian_int),
        ('toAddress', rlp.codec.binary),
        ('value', rlp.codec.big_endian_int),
        ('callData', rlp.codec.binary),
    )

    @classmethod
    def fromString(cls, s):
        return rlp.decode(s, NoChainTrx)

def create_call_tx(to_address, value, tx_data):
    tx = NoChainTrx(
        0, # nonce
        1, # gas price
        1000000, # gas limit
        bytearray(bytes.fromhex(to_address)), # toAddress, ERC20simple deployed contract address
        value, # value
        bytearray(bytes.fromhex(tx_data))
    )

    return rlp.encode(tx)

    # print("Constructing tx, to: {}, value: {}, tx_data: {}".format(to_address, value, tx_data))
    # tx = bytearray()

    # tx.append(bytearray(rlp.encode(0, rlp.codec.big_endian_int)))
    # tx.append(bytearray(rlp.encode(1, rlp.codec.big_endian_int)))
    # tx.append(bytearray(rlp.encode(100000000000, rlp.codec.big_endian_int)))
    # tx.append(bytearray(bytes.fromhex(to_address)))
    # tx.append(bytearray(rlp.encode(int(value), rlp.codec.big_endian_int)))
    # tx.append(bytearray(bytes.fromhex(to_address)))

    # print("Constructed tx: 0x{}".format(tx.hex()))
    # return tx

def execute_evm_tx(caller, rlp_encoded_tx):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    terra = LCDClient(
        url="https://bombay-lcd.terra.dev/",
        chain_id="bombay-12"
    )

    mk = MnemonicKey(mnemonic = mnemonic)
    wallet = terra.wallet(mk)

    gas_price_dict = requests.get("https://fcd.terra.dev/v1/txs/gas_prices").json()

    if len(rlp_encoded_tx) < tx_chunk_size:
        execute = MsgExecuteContract(
            wallet.key.acc_address,
            terranova_contract,
            {"execute_raw_ethereum_tx": {
                "caller_evm_address": list(bytes.fromhex(caller)),
                "unsigned_tx": list(rlp_encoded_tx)
            }},
        )

        execute_tx = wallet.create_and_sign_tx(
            CreateTxOptions(msgs=[execute], gas="auto",
            gas_prices=Coins(gas_price_dict),
            fee_denoms="uusd",
            gas_adjustment=1.5)
        )

        result = terra.tx.broadcast(execute_tx)

        return result

    else:
        k = keccak_256()
        k.update(rlp_encoded_tx)
        code_hash = k.hexdigest()
        print("Code hash: {}".format(code_hash))
        n_chunks = len(rlp_encoded_tx) // tx_chunk_size + (0 if len(rlp_encoded_tx) % tx_chunk_size == 0 else 1)
        for i in range(n_chunks):

            wallet = terra.wallet(mk)

            chunk = rlp_encoded_tx[i*tx_chunk_size:min((i+1) * tx_chunk_size, len(rlp_encoded_tx))]
            print("Length of chunk {}: {}".format(i, len(chunk)))
            execute = MsgExecuteContract(
                wallet.key.acc_address,
                terranova_contract,
                {"store_tx_chunk": {
                    "caller_evm_address": list(bytes.fromhex(caller_evm_address)),
                    "full_tx_hash": list(bytes.fromhex(code_hash)),
                    "chunk_index": i,
                    "chunk_data": list(chunk)
                }}
            )

            execute_tx = wallet.create_and_sign_tx(
                CreateTxOptions(msgs=[execute], gas="auto",
                gas_prices=Coins(gas_price_dict),
                fee_denoms="uusd",
                gas_adjustment=1.5)
            )

            result = terra.tx.broadcast(execute_tx)
            print("Result from trying to store chunk {}: {}".format(i, result))
            print("Sleeping 0.5 seconds")
            sleep(0.5)
        
        wallet = terra.wallet(mk)

        execute = MsgExecuteContract(
            wallet.key.acc_address,
            terranova_contract,
            {"execute_chunked_ethereum_tx": {
                "caller_evm_address": list(bytes.fromhex(caller_evm_address)),
                "full_tx_hash": list(bytes.fromhex(code_hash)),
                "chunk_count": n_chunks,
            }}
        )

        execute_tx = wallet.create_and_sign_tx(
            CreateTxOptions(msgs=[execute], gas="auto",
            gas_prices=Coins(gas_price_dict),
            fee_denoms="uusd",
            gas_adjustment=1.5)
        )

        result = terra.tx.broadcast(execute_tx)

        return result

def query_evm_tx(caller, rlp_encoded_tx):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    print("get event loop: {}".format(asyncio.get_event_loop()))

    terra = LCDClient(
        url="https://bombay-lcd.terra.dev/",
        chain_id="bombay-12"
    )

    query_json = {"raw_ethereum_query": {
        "caller_evm_address": list(bytes.fromhex(caller)),
        "unsigned_tx": list(rlp_encoded_tx)
    }}
    # print("Query json:  {}".format(query_json))
    result = terra.wasm.contract_query(terranova_contract, query_json)

    return result

def query_evm_account(evm_address):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    terra = LCDClient(
        url="https://bombay-lcd.terra.dev/",
        chain_id="bombay-12"
    )
    query_json = {"query_evm_account": {
        "evm_address": list(bytes.fromhex(evm_address)),
    }}

    result = terra.wasm.contract_query(terranova_contract, query_json)

    return result