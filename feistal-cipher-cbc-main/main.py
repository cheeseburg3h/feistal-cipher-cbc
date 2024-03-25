from cipher import FeistelCipher

def main():
    key = 0x12345678
    iv = 0x87654321

    cipher = FeistelCipher(key)

    test_inputs = [
        b"Hello, World!",
        b"This is a longer message that will be encrypted and decrypted using the Feistel cipher in CBC mode.",
        b"Symmetric encryption is an important concept in cryptography.",
        b"The quick brown fox jumps over the lazy dog.",
        b"Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    ]

    for i, plaintext in enumerate(test_inputs):
        print(f"Test Input {i+1}:")
        print("Plaintext:", plaintext)

        ciphertext = cipher.encrypt_cbc(plaintext, iv)
        print("Ciphertext:", ciphertext.hex())

        decrypted_plaintext = cipher.decrypt_cbc(ciphertext, iv)
        print("Decrypted Plaintext:", decrypted_plaintext)
        print()

if __name__ == "__main__":
    main()