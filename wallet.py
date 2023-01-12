import base58
import codecs
import hashlib

import utils

from ecdsa import NIST256p
from ecdsa import SigningKey

class Wallet(object):

    def __init__(self):
        self._private_key = SigningKey.generate(curve=NIST256p)
        self._public_key = self._private_key.get_verifying_key()
        # パブリックキーを短くまとめたものがブロックチェーンアドレス
        self._blockchain_address = self.generate_blockchain_address()

    @property
    def private_key(self):
        return self._private_key.to_string().hex()

    @property
    def public_key(self):
        return self._public_key.to_string().hex()

    @property
    def blockchain_address(self):
        return self._blockchain_address

    def generate_blockchain_address(self):
        ##########################
        # 2. SHA-256 for the public key
        public_key_bytes = self._public_key.to_string()
        # bpk: バイナリパブリックキー
        sha256_bpk = hashlib.sha256(public_key_bytes)
        # sha256_bpk = hashlib.sha256()
        # sha256_bpk.update(public_key_bytes)
        # ハッシュ生成
        sha256_bpk_digest = sha256_bpk.digest()
        ##########################
        # 3. Ripemd 160 for the SHA-256
        # Ripemd は SHA よりも短いハッシュを生成できる
        ripemd160_bpk = hashlib.new("ripemd160")
        ripemd160_bpk.update(sha256_bpk_digest)
        # ハッシュ作成
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, "hex")
        ##########################
        # 4. Add network bytes
        # メインネットワークに接続する際にバイナリで頭に 「00」 をつける
        network_byte = b"00"
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        # network_bitcoin_public_key = ripemd160_bpk_hex + network_byte
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, "hex"
        )
        ##########################
        # 5. Double SHA-256
        # 二重でSHA-256でハッシュ化
        sha256_bpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        sha256_2_bpk = hashlib.sha256(sha256_bpk_digest)
        sha256_2_bpk_digest = sha256_2_bpk.digest()
        sha256_hex = codecs.encode(sha256_2_bpk_digest, "hex")
        ##########################
        # 6. Get checksum
        # 
        checksum = sha256_hex[:8]
        ##########################
        # 7. 
        # 
        address_hex = (network_bitcoin_public_key + checksum).decode("utf-8")
        # address_hex = (checksum + network_bitcoin_public_key).decode("utf-8")
        ##########################
        # 8. 
        # 
        blockchain_address = base58.b58encode(address_hex).decode("utf-8")
        return blockchain_address



class Transaction(object):

    def __init__(self, sender_private_key, sender_public_key,
                sender_blockchain_address, recipient_blockchain_address,
                value):
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_public_key
        self.sender_blockchain_address = sender_blockchain_address
        self.recipient_blockchain_address = recipient_blockchain_address
        self.value = value

    def generate_signature(self):
        transaction = utils.sorted_dict_by_key({
            "sender_blockchain_address": self.sender_blockchain_address,
            "recipient_blockchain_address": self.recipient_blockchain_address,
            "value": self.value
        })
        # sha256.update(str(transaction).encode("utf-8"))
        sha256 = hashlib.sha256(str(transaction).encode("utf-8"))
        # ハッシュ化
        message = sha256.digest()
        private_key = SigningKey.from_string(
            bytes().fromhex(self.sender_private_key), curve=NIST256p
        )
        private_key_sign = private_key.sign(message)
        signature = private_key_sign.hex()
        return signature



if __name__ == "__main__":
    wallet_M = Wallet()
    wallet_A = Wallet()
    wallet_B = Wallet()
    t = Transaction(
        wallet_A.private_key, wallet_A.public_key, wallet_A.blockchain_address, wallet_B.blockchain_address, 1.0
    )
    print(t.generate_signature())

    # blockchain Node
    import blockchain
    block_chain = blockchain.BlockChain(blockchain_address=wallet_M.blockchain_address)
    is_added = block_chain.add_transaction(
        wallet_A.blockchain_address,
        wallet_B.blockchain_address,
        1.0,
        wallet_A.public_key,
        t.generate_signature()
    )
    print("Added?", is_added)
    block_chain.mining()
    utils.pprint(block_chain.chain)

    print("A", block_chain.calculate_total_amount(wallet_A.blockchain_address))
    print("B", block_chain.calculate_total_amount(wallet_B.blockchain_address))
