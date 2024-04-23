import argparse
import os
import struct

parser = argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument('-c')
parser.add_argument('-i', action='append')
parser.add_argument('-n')
parser.add_argument('-y', '--why')
parser.add_argument('-p')
parser.add_argument('-g')
action = parser.parse_args()

# get the file path from the environment variable
#file_path = os.getenv('BCHOC_FILE_PATH')

structformat = "32s d 32s 32s 12s 12s 12s I"

# get the file path from the environment variable
def get_file_path():
    file_path = os.getenv("BCHOC_FILE_PATH")
    if file_path:
        return file_path
    else:
        # replace with your local path for testing
        return

# check for blocks
def check_existing_blocks(file_path):
    return os.path.isfile(file_path)

# construct genesis block
def create_genesis_block(file_path):
    
    dynamicformat = structformat + " 14s"
    block_format = struct.Struct(dynamicformat)
    
    with open(file_path, "wb") as file:
        # genesis block data
        prev_hash = b"\0" * 32
        timestamp = 0
        case_id = b"0" * 32
        evidence_id = b"0" * 32
        state = b"INITIAL\0\0\0\0\0"
        creator = b"\0" * 12
        owner = b"\0" * 12
        d_length = 14
        data = b"Initial block\0"
        
        # Pack data into binary format
        block_data = block_format.pack(
            prev_hash, timestamp, case_id, evidence_id,
            state, creator, owner, d_length, data
        )
        
        # Write block data to file
        file.write(block_data)

def main():
    file_path = get_file_path()
    if not check_existing_blocks(file_path):
        create_genesis_block(file_path)
        print("genesis block created.")
    else:
        print("blockchain already exists.")

if __name__ == "__main__":
    main()
