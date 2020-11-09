import requests
from binascii import unhexlify, hexlify
import string
TARGET = 'http://crypto-class.appspot.com/po?er='
# --------------------------------------------------------------
# padding oracle
# --------------------------------------------------------------


def padding_oracle_query(ciphertext):
    ciphertext_str = hexlify(ciphertext).decode('ascii')
    r = requests.get(TARGET + ciphertext_str)
    return True if r.status_code == 404 else False


def decrypt_bloc(previous_block, block_to_decipher):
    clear_bloc = bytearray(len(block_to_decipher))
    padding_values = list(range(1, 17))
    guess_possible_values = [ord(c) for c in string.ascii_letters + string.whitespace] + padding_values

    #For each byte in block starting from the last
    for guess_pos in range(block_size - 1, -1, -1):
        # For each possible guess value
        for guess_value in guess_possible_values:
            #We get back the original ciphertext bloc
            guess_bloc = previous_block.copy()
            padding_value = block_size - guess_pos

            #If we are at the last byte of a bloc and guess_value == padding value,
            #we send the original ciphertext. So if the original ciphertext is a valid padding
            #value or if we are at the last block we will get a wrong guess.
            if guess_pos == (block_size - 1) and guess_value == padding_value:
                continue

            #We xor the values and the padding to the indexes we already already guessed
            for index_to_pad in range(block_size - 1, guess_pos, -1):
                clear_value = clear_bloc[index_to_pad]
                guess_bloc[index_to_pad] ^= clear_value ^ padding_value

            #We apply the guess at the current position
            guess_bloc[guess_pos] ^= guess_value ^ padding_value
            new_ciphertext = guess_bloc + block_to_decipher

            #We query the server
            is_padding_error = padding_oracle_query(new_ciphertext)

            #If we got a padding error it means that the guess is correct
            if is_padding_error is True:
                clear_bloc[guess_pos] = guess_value
                break
    return clear_bloc


if __name__ == "__main__":
    block_size = 16
    c = 'f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
    c_bytearray = bytearray(unhexlify(c))
    cipher_blocs = [c_bytearray[i:i + block_size] for i in range(0, len(c_bytearray), block_size)]

    clear_text = ""
    number_of_blocks = len(cipher_blocs)

    #Block 0 is the IV so we start to decrypt at index 1
    for block_index in range(1, number_of_blocks):
        block_to_decipher = cipher_blocs[block_index]
        previous_block = cipher_blocs[block_index - 1]
        decrypted_bloc = decrypt_bloc(cipher_blocs[block_index - 1], cipher_blocs[block_index])
        decrypted_bloc = decrypted_bloc.decode('ascii')
        print(decrypted_bloc)
        clear_text += decrypted_bloc

    print(clear_text)
    #"The Magic Words are Squeamish Ossifrage					"
