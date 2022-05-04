# from proxy.common_neon.eth_proto import NoChainTrx
import rlp

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

tx = NoChainTrx(100, 1, 100000, 0xd3CdA913deB6f67967B99D67aCDFa1712C293601.to_bytes(20, 'big'), 123456, b'')

print(rlp.encode(tx))
print(rlp.encode(tx).hex())
