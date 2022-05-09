import base64
from terra_sdk.client.lcd.api.tx import CreateTxOptions
from terra_sdk.client.localterra import LocalTerra
from terra_sdk.core.wasm import MsgStoreCode, MsgInstantiateContract, MsgExecuteContract
from terra_sdk.core.fee import Fee
from terra_sdk.core.coins import Coins
from terra_sdk.client.lcd import LCDClient
from terra_sdk.key.mnemonic import MnemonicKey
import json
# terra = LocalTerra()
#test1 = terra.wallets["test1"]

terra = LCDClient(url="https://bombay-lcd.terra.dev/", chain_id="bombay-12")
mk = MnemonicKey("notice oak worry limit wrap speak medal online prefer cluster roof addict wrist behave treat actual wasp year salad speed social layer crew genius")
test1 = terra.wallet(mk)

contract_address = "terra1ffdkykc57rp2my0pyaqqezcjrudyhs4p6pa4xj"
unsigned_tx = "f90dd28001839896808080b90dc76080604052678ac7230489e8000060025534801561001c57600080fd5b506002546000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550610d56806100716000396000f3fe608060405234801561001057600080fd5b50600436106100935760003560e01c8063313ce56711610066578063313ce5671461013457806370a082311461015257806395d89b4114610182578063a9059cbb146101a0578063dd62ed3e146101d057610093565b806306fdde0314610098578063095ea7b3146100b657806318160ddd146100e657806323b872dd14610104575b600080fd5b6100a0610200565b6040516100ad9190610b27565b60405180910390f35b6100d060048036038101906100cb9190610a66565b610239565b6040516100dd9190610b0c565b60405180910390f35b6100ee61032b565b6040516100fb9190610b49565b60405180910390f35b61011e60048036038101906101199190610a13565b610335565b60405161012b9190610b0c565b60405180910390f35b61013c61069b565b6040516101499190610b64565b60405180910390f35b61016c600480360381019061016791906109a6565b6106a0565b6040516101799190610b49565b60405180910390f35b61018a6106e8565b6040516101979190610b27565b60405180910390f35b6101ba60048036038101906101b59190610a66565b610721565b6040516101c79190610b0c565b60405180910390f35b6101ea60048036038101906101e591906109d3565b6108f5565b6040516101f79190610b49565b60405180910390f35b6040518060400160405280600f81526020017f54657272616e6f7661204552433230000000000000000000000000000000000081525081565b600081600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516103199190610b49565b60405180910390a36001905092915050565b6000600254905090565b60008060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205482111561038257600080fd5b600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205482111561040b57600080fd5b816000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546104559190610bf1565b6000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555081600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205461051f9190610bf1565b600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546105e99190610b9b565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516106889190610b49565b60405180910390a3600190509392505050565b601281565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b6040518060400160405280600481526020017f4e4f56410000000000000000000000000000000000000000000000000000000081525081565b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205482111561076e57600080fd5b816000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546107b89190610bf1565b6000803373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020546108449190610b9b565b6000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516108e39190610b49565b60405180910390a36001905092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b60008135905061098b81610cf2565b92915050565b6000813590506109a081610d09565b92915050565b6000602082840312156109bc576109bb610cdc565b5b60006109ca8482850161097c565b91505092915050565b600080604083850312156109ea576109e9610cdc565b5b60006109f88582860161097c565b9250506020610a098582860161097c565b9150509250929050565b600080600060608486031215610a2c57610a2b610cdc565b5b6000610a3a8682870161097c565b9350506020610a4b8682870161097c565b9250506040610a5c86828701610991565b9150509250925092565b60008060408385031215610a7d57610a7c610cdc565b5b6000610a8b8582860161097c565b9250506020610a9c85828601610991565b9150509250929050565b610aaf81610c37565b82525050565b6000610ac082610b7f565b610aca8185610b8a565b9350610ada818560208601610c7a565b610ae381610ce1565b840191505092915050565b610af781610c63565b82525050565b610b0681610c6d565b82525050565b6000602082019050610b216000830184610aa6565b92915050565b60006020820190508181036000830152610b418184610ab5565b905092915050565b6000602082019050610b5e6000830184610aee565b92915050565b6000602082019050610b796000830184610afd565b92915050565b600081519050919050565b600082825260208201905092915050565b6000610ba682610c63565b9150610bb183610c63565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03821115610be657610be5610cad565b5b828201905092915050565b6000610bfc82610c63565b9150610c0783610c63565b925082821015610c1a57610c19610cad565b5b828203905092915050565b6000610c3082610c43565b9050919050565b60008115159050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b600060ff82169050919050565b60005b83811015610c98578082015181840152602081019050610c7d565b83811115610ca7576000848401525b50505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b6000601f19601f8301169050919050565b610cfb81610c25565b8114610d0657600080fd5b50565b610d1281610c63565b8114610d1d57600080fd5b5056fea2646970667358221220fd73d39b0f9762fc4ab42cde5b96e2b9cca69e87e5b45403fcc50bc76d377b9b64736f6c63430008070033"
eth_sender = "B34e2213751c5d8e9a31355fcA6F1B4FA5bB6bE1"
eth_receiver = "2e36b2970ab7A4C955eADD836585c21A087Ab904"
# Pass an unsigned Ethereum TX to the EVM
# Create a contract
"""
execute = MsgExecuteContract(
    test1.key.acc_address,
    contract_address,
    {"call_from_raw_ethereum_t_x": {
        "caller_evm_address": list(bytes.fromhex(eth_sender)),
        "unsigned_tx": list(bytes.fromhex(unsigned_tx))
    }},
    {"uluna": 100000},
)

execute_tx = test1.create_and_sign_tx(
    CreateTxOptions(msgs=[execute], fee=Fee(1000000, Coins(uluna=1000000)))
)

execute_tx_result = terra.tx.broadcast(execute_tx)
print(execute_tx_result)
"""

query_tx = "f84180018398968094ff3b783539a1a7a53ecacfb1c0778274c670f35b80a470a08231000000000000000000000000b34e2213751c5d8e9a31355fca6f1b4fa5bb6be1"
# # Query the balance
# query_balance = MsgExecuteContract(
#     test1.key.acc_address,
#     contract_address,
#     {"call_from_raw_ethereum_t_x": {
#         "caller_evm_address": list(bytes.fromhex(eth_sender)),
#         "unsigned_tx": list(bytes.fromhex(query_tx))
#     }},
#     {"uluna": 100000},
# )
# query_balance_result = terra.tx.broadcast(query_balance)
# print(query_balance_result)

query_balance_tx = CreateTxOptions(
    msgs = [
        MsgExecuteContract(
            sender=test1.key.acc_address,
            contract=contract_address,
            execute_msg={"call_from_raw_ethereum_t_x": {
                    "caller_evm_address": list(bytes.fromhex(eth_sender)),
                    "unsigned_tx": list(bytes.fromhex(query_tx))
                    # "unsigned_tx": list(bytes.fromhex("abcd1234"))
            }},
        )
    ],
    gas="auto",
    fee_denoms="uusd",
)


print("EVM tx: query ERC20 balance of sender 0x{}".format(eth_sender))
print("Using terra address {} to send tx".format(test1.key.acc_address))
tx = test1.create_and_sign_tx(options=query_balance_tx)
result = terra.tx.broadcast(tx)
value = json.loads(result.raw_log)[0]['events'][1]['attributes'][2]['value']
print("Queried NOVA balance of sender 0x{}: {}".format(eth_sender, int(value[2:], 16)))
print("tx hash on Terra testnet: {}\n".format(result.txhash))

# result = terra.wasm.contract_query(contract_address, {"get_count": {}})
# print(result)

send_tx = "f86280018398968094ff3b783539a1a7a53ecacfb1c0778274c670f35b80b844a9059cbb0000000000000000000000002e36b2970ab7a4c955eadd836585c21a087ab9040000000000000000000000000000000000000000000000000000000000012fd1"
send_token = CreateTxOptions(
    msgs = [
        MsgExecuteContract(
            sender=test1.key.acc_address,
            contract=contract_address,
            execute_msg={"call_from_raw_ethereum_t_x": {
                    "caller_evm_address": list(bytes.fromhex(eth_sender)),
                    "unsigned_tx": list(bytes.fromhex(send_tx))
                    # "unsigned_tx": list(bytes.fromhex("abcd1234"))
            }},
        )
    ],
    gas="auto",
    fee_denoms="uusd",
)

print("Transferring NOVA tokens from {} to {}".format(eth_sender, eth_receiver))
tx = test1.create_and_sign_tx(options=send_token)
result = terra.tx.broadcast(tx)
print("tx hash on Terra testnet: {}\n".format(result.txhash))

query_tx_2 = "f84180018398968094ff3b783539a1a7a53ecacfb1c0778274c670f35b80a470a082310000000000000000000000002e36b2970ab7a4c955eadd836585c21a087ab904"
query_balance_tx = CreateTxOptions(
    msgs = [
        MsgExecuteContract(
            sender=test1.key.acc_address,
            contract=contract_address,
            execute_msg={"call_from_raw_ethereum_t_x": {
                    "caller_evm_address": list(bytes.fromhex(eth_sender)),
                    "unsigned_tx": list(bytes.fromhex(query_tx_2))
                    # "unsigned_tx": list(bytes.fromhex("abcd1234"))
            }},
        )
    ],
    gas="auto",
    fee_denoms="uusd",
)


print("EVM tx: query ERC20 balance of receiver 0x{}".format(eth_receiver))
print("Using terra address {} to send tx".format(test1.key.acc_address))
tx = test1.create_and_sign_tx(options=query_balance_tx)
result = terra.tx.broadcast(tx)
value = json.loads(result.raw_log)[0]['events'][1]['attributes'][2]['value']
print("Queried NOVA balance of reciever 0x{}: {}".format(eth_receiver, int(value[2:], 16)))
print("tx hash on Terra testnet: {}\n".format(result.txhash))
