import traceback
from datetime import datetime
from proxy.environment import ELF_PARAMS
from proxy.common_neon.permission_token import PermissionToken
from solana.publickey import PublicKey
from solana.account import Account as SolanaAccount
from typing import Union
from proxy.common_neon.address import EthereumAddress
from logged_groups import logged_group
from ..common_neon.solana_interactor import SolanaInteractor

NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE = int(ELF_PARAMS.get("NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE", 0))
NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE = int(ELF_PARAMS.get("NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE", 0))
ALLOWANCE_TOKEN_ADDR = ELF_PARAMS.get("NEON_PERMISSION_ALLOWANCE_TOKEN", '')
DENIAL_TOKEN_ADDR = ELF_PARAMS.get("NEON_PERMISSION_DENIAL_TOKEN", '')


@logged_group("neon.AccountWhitelist")
class AccountWhitelist:
    def __init__(self, solana: SolanaInteractor, permission_update_int: int):
        self.solana = solana
        self.account_cache = {}
        self.permission_update_int = permission_update_int
        self.allowance_token = None
        self.denial_token = None

        if ALLOWANCE_TOKEN_ADDR == '' and DENIAL_TOKEN_ADDR == '':
            return

        if ALLOWANCE_TOKEN_ADDR == '' or DENIAL_TOKEN_ADDR == '':
            self.error(f'Wrong proxy configuration: allowance and denial tokens must both exist or absent!')
            raise Exception("NEON service is unhealthy. Try again later")

        self.allowance_token = PermissionToken(self.solana, PublicKey(ALLOWANCE_TOKEN_ADDR))
        self.denial_token = PermissionToken(self.solana, PublicKey(DENIAL_TOKEN_ADDR))

    def read_balance_diff(self, ether_addr: Union[str, EthereumAddress]) -> int:
        token_list = [
            self.allowance_token.get_token_account_address(ether_addr),
            self.denial_token.get_token_account_address(ether_addr)
        ]

        balance_list = self.solana.get_token_account_balance_list(token_list)
        allowance_balance = balance_list[0]
        denial_balance = balance_list[1]
        return allowance_balance - denial_balance

    def grant_permissions(self, ether_addr: Union[str, EthereumAddress], min_balance: int, signer: SolanaAccount):
        try:
            diff = self.read_balance_diff(ether_addr)
            if diff >= min_balance:
                self.info(f'{ether_addr} already has permission')
                return True

            to_mint = min_balance - diff
            self.allowance_token.mint_to(to_mint, ether_addr, signer)
            self.info(f'Permissions granted to {ether_addr}')
            return True
        except Exception as err:
            self.error(f'Failed to grant permissions to {ether_addr}: {type(err)}: {err}')
            return False

    def deprive_permissions(self, ether_addr: Union[str, EthereumAddress], min_balance: int, signer: SolanaAccount):
        try:
            diff = self.read_balance_diff(ether_addr)
            if diff < min_balance:
                self.info(f'{ether_addr} already deprived')
                return True

            to_mint = diff - min_balance + 1
            self.denial_token.mint_to(to_mint, ether_addr, signer)
            self.info(f'Permissions deprived to {ether_addr}')
            return True
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f'Failed to grant permissions to {ether_addr}: ' +
                       f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')
            return False

    def grant_client_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.grant_permissions(ether_addr, NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE)

    def grant_contract_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.grant_permissions(ether_addr, NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE)

    def deprive_client_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.deprive_permissions(ether_addr, NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE)

    def deprive_contract_permissions(self, ether_addr: Union[str, EthereumAddress]):
        return self.deprive_permissions(ether_addr, NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE)

    def get_current_time(self):
        return datetime.now().timestamp()

    def has_permission(self, ether_addr: Union[str, EthereumAddress], min_balance: int):
        if self.allowance_token is None and self.denial_token is None:
            return True

        cached = self.account_cache.get(ether_addr, None)
        current_time = self.get_current_time()
        if cached is not None:
            diff = current_time - cached['last_update']
            if diff < self.permission_update_int:
                return cached['diff'] >= min_balance

        try:
            diff = self.read_balance_diff(ether_addr)
            self.account_cache[ether_addr] = {
                'last_update': current_time,
                'diff': diff
            }
            return diff >= min_balance
        except Exception as err:
            err_tb = "".join(traceback.format_tb(err.__traceback__))
            self.error(f'Failed to read permissions for {ether_addr}: ' +
                       f'Type(err): {type(err)}, Error: {err}, Traceback: {err_tb}')

    def has_client_permission(self, ether_addr: Union[str, EthereumAddress]):
        return self.has_permission(ether_addr, NEON_MINIMAL_CLIENT_ALLOWANCE_BALANCE)

    def has_contract_permission(self, ether_addr: Union[str, EthereumAddress]):
        return self.has_permission(ether_addr, NEON_MINIMAL_CONTRACT_ALLOWANCE_BALANCE)
