import os
import binascii
from Crypto.Hash import SHA256

def get_block(f, pos, block_size):
    f.seek(pos)
    return f.read(block_size)

def get_hash(filename, block_size):
    with open(filename, 'rb') as f:
        file_size = os.path.getsize(filename)

        # We treat the last block of variable length
        last_block_size = file_size % block_size
        last_block_pos = file_size - last_block_size

        last_block = get_block(f, last_block_pos, last_block_size)

        h = SHA256.new(last_block)
        last_block_hash = h.digest()

        # We treat the whole file minus the last block
        # Hence the 'file_size - last_block_size - block_size'
        for pos in range(file_size - last_block_size - block_size, -1, -block_size):
            block = get_block(f, pos, block_size)

            # Concatenate block with hash of previous block
            block = block + last_block_hash

            # Hash new block
            h = SHA256.new(block)
            last_block_hash = h.digest()

        return binascii.hexlify(last_block_hash).decode('ascii')


if __name__ == '__main__':

    video_1_filename = '6.1.intro.mp4_download'
    video_2_filename = '6.2.birthday.mp4_download'

    block_size = 1024

    video_1_hash = get_hash(video_1_filename, block_size)
    print(video_1_hash) # == '5b96aece304a1422224f9a41b228416028f9ba26b0d1058f400200f06a589949'
    video_2_hash = get_hash(video_2_filename, block_size)
    print(video_2_hash) # == '03c08f4ee0b576fe319338139c045c89c3e8e9409633bea29442e21425006ea8'
