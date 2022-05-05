import base64
from terra_sdk.client.lcd.api.tx import CreateTxOptions
from terra_sdk.client.localterra import LocalTerra
from terra_sdk.core.wasm import MsgStoreCode, MsgInstantiateContract, MsgExecuteContract
from terra_sdk.core.fee import Fee
from terra_sdk.core.coins import Coins

terra = LocalTerra()
test1 = terra.wallets["test1"]

contract_address = "terra18vd8fpwxzck93qlwghaj6arh4p7c5n896xzem5"
unsigned_tx = "f903928001830186a08080b903876080604052336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555034801561005057600080fd5b50610327806100606000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c8063445df0ac146100465780638da5cb5b14610064578063fdacd57614610082575b600080fd5b61004e61009e565b60405161005b9190610179565b60405180910390f35b61006c6100a4565b60405161007991906101d5565b60405180910390f35b61009c60048036038101906100979190610221565b6100c8565b005b60015481565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b60008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610156576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161014d906102d1565b60405180910390fd5b8060018190555050565b6000819050919050565b61017381610160565b82525050565b600060208201905061018e600083018461016a565b92915050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006101bf82610194565b9050919050565b6101cf816101b4565b82525050565b60006020820190506101ea60008301846101c6565b92915050565b600080fd5b6101fe81610160565b811461020957600080fd5b50565b60008135905061021b816101f5565b92915050565b600060208284031215610237576102366101f0565b5b60006102458482850161020c565b91505092915050565b600082825260208201905092915050565b7f546869732066756e6374696f6e206973207265737472696374656420746f207460008201527f686520636f6e74726163742773206f776e657200000000000000000000000000602082015250565b60006102bb60338361024e565b91506102c68261025f565b604082019050919050565b600060208201905081810360008301526102ea816102ae565b905091905056fea26469706673582212202772102c6bf65909b8a1ed2bbf4af4f042e10a1097612ea089ae207eeb38038964736f6c634300080d0033"

# Pass an unsigned Ethereum TX to the EVM
execute = MsgExecuteContract(
    test1.key.acc_address,
    contract_address,
    {"call_from_raw_ethereum_t_x": {
        "caller_evm_address": list(bytes.fromhex("38ff0dc6321c1e7de65e150412bc945e8b6b1a81")),
        "unsigned_tx": list(bytes.fromhex(unsigned_tx))
    }},
    {"uluna": 100000},
)

execute_tx = test1.create_and_sign_tx(
    CreateTxOptions(msgs=[execute], fee=Fee(1000000, Coins(uluna=1000000)))
)

execute_tx_result = terra.tx.broadcast(execute_tx)
print(execute_tx_result)

# result = terra.wasm.contract_query(contract_address, {"get_count": {}})
# print(result)
