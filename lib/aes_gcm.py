from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from lib.finite_field import FFPoly

import base64

def pad(data: bytes, ignore_empty: bool=False) -> bytes:
    if len(data) == 0:
        if ignore_empty:
            return data
        else:
            return b'\x00' * 16
    if len(data) % 16 == 0: return data

    missing = 16 - (len(data) % 16)
    return data + (b'\x00' * missing)

class GHASH:
    def __init__(self, auth_key: bytes, associated_data: bytes, ciphertext: bytes):
        ciphertext_length = len(ciphertext) * 8
        associated_data_length = len(associated_data) * 8
        associated_data = pad(associated_data)
        ciphertext = pad(ciphertext, True)

        # prepare ciphertext blocks and split into 16 byte blocks
        self._C = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

        # prepare associated data blocks and split into 16 byte blocks
        self._A = [associated_data[i:i+16] for i in range(0, len(associated_data), 16)]

        self._H = auth_key
        self._L = (associated_data_length).to_bytes(8, "big") + (ciphertext_length).to_bytes(8, "big")

    @property
    def L(self) -> bytes:
        return self._L

    def digest(self) -> bytes:
        h = FFPoly(self._H)

        # initialize hash with zero block
        out_hash = FFPoly(b"\x00" * 16)

        # iterate over associated data blocks
        for a in self._A:
            out_hash = (out_hash ^ FFPoly(a)) * h

        # iterate over ciphertext blocks
        for c in self._C:
            out_hash = (out_hash ^ FFPoly(c)) * h

        # add length block
        out_hash = (out_hash ^ FFPoly(self._L)) * h
        return out_hash.block

class AES_GCM:
    def __init__(self, key: bytes, nonce: bytes):
        assert len(key) == 16, "Invalid key length"
        assert len(nonce) == 12, "Invalid nonce length"

        self._key = key
        self._nonce = nonce
        self._associated_data = None
        self._counter = 1
        self._tag = None
        self._ciphertext = None
        self._aes = Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend()).encryptor()

    @property
    # returns current counter value and automatically increments counter
    def __counter_val(self) -> bytes:
        val = self._nonce + self._counter.to_bytes(4, "big")
        self._counter += 1
        return val

    @property
    def __next_block(self) -> bytes:
        return self._aes.update(self.__counter_val)

    def update(self, associated_data: bytes) -> None:
        self._associated_data = associated_data

    # only encryption part, not mac
    def encrypt(self, plaintext: bytes):
        assert self._associated_data is not None, "Associated data is not set"
        #assert len(plaintext) % 16 == 0, "Plaintext must be a multiple of 16 bytes"

        # Get first block (y0) for auth tag
        Y0 = self.__counter_val
        # Encrypt Y0
        Y0_encrypted = self._aes.update(Y0)

        # Generate auth key H
        H = self._aes.update(b"\x00" * 16)

        # Prepare all plaintext blocks and split into 16 byte blocks
        plaintext_blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

        self._ciphertext = bytearray()
        for i, p in enumerate(plaintext_blocks):
            # Prepare next encrypted block
            next_block = self.__next_block
            # next_block must be of the same length as the plaintext block
            next_block = next_block[:len(p)]

            c_block = FFPoly(next_block)
            p_block = FFPoly(p)

            ciphertext = (c_block ^ p_block).block

            if len(p) != 16: ciphertext = ciphertext.lstrip(b'\x00')

            # append to ciphertext
            self._ciphertext += ciphertext

        # convert ciphertext to bytes
        self._ciphertext = bytes(self._ciphertext)

        # Generate GHASH
        ghash = GHASH(H, self._associated_data, self._ciphertext)

        # Generate auth tag
        self._tag = FFPoly(ghash.digest()) ^ FFPoly(Y0_encrypted)

        return self._ciphertext, self._tag.block, Y0, H
