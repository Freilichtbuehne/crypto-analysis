from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AES_CBC:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())

    def xor(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, data):
        encryptor = self.cipher.encryptor()
        padder = padding.PKCS7(16 * 8).padder()
        padded_data = padder.update(data) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def encrypt_raw(self, data):
        encryptor = self.cipher.encryptor()
        return encryptor.update(data) + encryptor.finalize()

    def unpad(self, data):
        unpadder = padding.PKCS7(16 * 8).unpadder()
        try:
            return unpadder.update(data) + unpadder.finalize()
        except ValueError:
            return None

    def decrypt(self, data):
        decryptor = self.cipher.decryptor()
        return decryptor.update(data) + decryptor.finalize()