from typing import Optional

from ..indexer.base_db import BaseDB, DBQuery
from ..common_neon.utils import SolanaBlockInfo


# FIXME: Use an actual DB <nsomani>
GENESIS_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000"
GENESIS_BLOCK = SolanaBlockInfo(
    slot=0,
    hash=GENESIS_HASH,
    parent_hash=GENESIS_HASH
)
blocks_by_hash = {GENESIS_HASH: GENESIS_BLOCK}
blocks_by_slot = {0: GENESIS_BLOCK}


class SolanaBlocksDB:
    def __init__(self):
        # BaseDB.__init__(self, 'solana_block')
        self._column_lst = ('slot', 'hash')
        self._full_column_lst = ('slot', 'hash', 'parent_hash', 'blocktime', 'signatures')

    def _block_from_value(self, slot: Optional[int], values: []) -> SolanaBlockInfo:
        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            is_finalized=True,
            slot=values[0],
            hash=values[1],
        )

    def _full_block_from_value(self, slot: Optional[int], values: []) -> SolanaBlockInfo:
        if not values:
            return SolanaBlockInfo(slot=slot)

        return SolanaBlockInfo(
            is_finalized=True,
            slot=values[0],
            hash=values[1],
            parent_hash=values[2],
            time=values[3],
            signs=self.decode_list(values[4])
        )

    def get_block_by_slot(self, block_slot: int) -> SolanaBlockInfo:
        return blocks_by_slot[block_slot]
        # q = DBQuery(column_list=self._column_lst, key_list=[('slot', block_slot)], order_list=[])
        # return self._block_from_value(block_slot, self._fetchone(q))

    def get_full_block_by_slot(self, block_slot) -> SolanaBlockInfo:
        return blocks_by_slot[block_slot]
        # q = DBQuery(column_list=self._full_column_lst, key_list=[('slot', block_slot)], order_list=[])
        # return self._block_from_value(block_slot, self._fetchone(q))

    def get_block_by_hash(self, block_hash) -> SolanaBlockInfo:
        return blocks_by_hash[block_hash]
        # q = DBQuery(column_list=self._column_lst, key_list=[('hash', block_hash)], order_list=[])
        # return self._block_from_value(None, self._fetchone(q))

    def set_block(self, block: SolanaBlockInfo):
        blocks_by_hash[block.hash] = block
        blocks_by_slot[block.slot] = block
        """
        with self._conn.cursor() as cursor:
            cursor.execute(f'''
                INSERT INTO {self._table_name}
                ({', '.join(self._full_column_lst)})
                VALUES
                ({', '.join(['%s' for _ in range(len(self._full_column_lst))])})
                ON CONFLICT DO NOTHING;
                ''',
                (block.slot, block.hash, block.parent_hash, block.time, self.encode_list(block.signs)))
        """
