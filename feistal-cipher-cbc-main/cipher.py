from galois import GF

class FeistelCipher:
    def __init__(self, key):
        self.key = key
        self.gf = GF(2**16)
        self.subkeys = self.generate_subkeys()

    def generate_subkeys(self):
        subkeys = []
        for i in range(16):
            subkey = (self.key >> (i * 2)) & 0xFFFF
            subkeys.append(subkey)
        return subkeys

    def f_function(self, x, subkey):
        x_gf = self.gf(x)
        subkey_gf = self.gf(subkey)
        result = (x_gf * x_gf * x_gf) + subkey_gf
        return int(result)

    def encrypt_block(self, block):
        left, right = block >> 16, block & 0xFFFF
        for i in range(16):
            temp = right
            right = left ^ self.f_function(right, self.subkeys[i])
            left = temp
        return (left << 16) | right

    def decrypt_block(self, block):
        left, right = block >> 16, block & 0xFFFF
        for i in range(15, -1, -1):
            temp = right
            right = left ^ self.f_function(right, self.subkeys[i])
            left = temp
        return (left << 16) | right

    def encrypt_cbc(self, plaintext, iv):
        ciphertext = []
        prev_block = iv
        for i in range(0, len(plaintext), 4):
            block = int.from_bytes(plaintext[i:i+4], byteorder='big')
            block ^= prev_block
            encrypted_block = self.encrypt_block(block)
            ciphertext.append(encrypted_block.to_bytes(4, byteorder='big'))
            prev_block = encrypted_block
        return b''.join(ciphertext)

    def decrypt_cbc(self, ciphertext, iv):
        plaintext = []
        prev_block = iv
        for i in range(0, len(ciphertext), 4):
            block = int.from_bytes(ciphertext[i:i+4], byteorder='big')
            decrypted_block = self.decrypt_block(block)
            decrypted_block ^= prev_block
            plaintext.append(decrypted_block.to_bytes(4, byteorder='big'))
            prev_block = block
        return b''.join(plaintext)