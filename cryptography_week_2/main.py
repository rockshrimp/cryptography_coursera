from binascii import unhexlify
from Crypto.Cipher import AES

def xor(a,b):
    return ''.join([chr(x ^ y) for x, y in zip(a, b)])

def CBC_decrypt(key, cipher_text, block_size):
    key = unhexlify(CBC_key)
    ciphertext = unhexlify(hex_encoded_ciphertext)

    plaintext = ''
    blocs = [ciphertext[i: i + block_size] for i in range(0, len(ciphertext), block_size)]

    for i in range(1, len(blocs)):
        ciphertext_bloc = blocs[i]
        xor_bloc = blocs[i - 1]
        xored_text = AES.new(key, AES.MODE_ECB).decrypt(ciphertext_bloc)

        plaintext += xor(xor_bloc, xored_text)

    # Remove padding
    plaintext = plaintext[:-ord(plaintext[-1])]

    print(plaintext)
    return plaintext


def CTR_decrypt(key, cipher_text, block_size):
    iv = unhexlify(cipher_text[:block_size * 2])
    key = unhexlify(key)
    ciphertext = unhexlify(cipher_text[block_size * 2:])

    blocs = (ciphertext[i: i + block_size] for i in range(0, len(ciphertext), block_size))

    plaintext = ''
    for i, cipher_block in enumerate(blocs):
        iv_inc = int.from_bytes(iv, 'big') + i
        iv_inc = bytearray(iv_inc.to_bytes(len(iv), 'big'))
        iv_encrypted = AES.new(key, AES.MODE_ECB).encrypt(iv_inc)
        plaintext += xor(cipher_block, iv_encrypted)

    print(plaintext)
    return plaintext

if __name__ == '__main__':
    CBC_key = b'140b41b22a29beb4061bda66b6747e14'
    CBC_ciphertexts = [
        b'4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81',
        b'5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253']

    CTR_key = b'36f18357be4dbd77f050515c73fcf9f2'
    CTR_ciphertexts = [
        b'69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329',
        b'770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451']

    block_size = AES.block_size

    for hex_encoded_ciphertext in CBC_ciphertexts:
        ## Using AES.MODE_CBC
        key = unhexlify(CBC_key)
        IV = unhexlify(hex_encoded_ciphertext)[:block_size]
        ciphertext = unhexlify(hex_encoded_ciphertext)[block_size:]
        data = AES.new(key, AES.MODE_CBC, iv=IV).decrypt(ciphertext)
        result_1 = data[:-data[-1]]

        ## Using AES.MODE_ECB
        result_2 = CBC_decrypt(CBC_key, hex_encoded_ciphertext, block_size)

    for hex_encoded_ciphertext in CTR_ciphertexts:
        ## Using AES.MODE_ECB
        key = CTR_key
        CTR_decrypt(key, hex_encoded_ciphertext, block_size)

#Basic CBC mode encryption needs padding.
#Our implementation uses rand. IV
#CTR mode lets you build a stream cipher from a block cipher.
#Always avoid the two time pad!
