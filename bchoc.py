#!/usr/bin/env python3

import argparse
import os
import struct
import sys
import hashlib
import datetime
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from uuid import UUID

#parser = argparse.ArgumentParser()
#parser.add_argument("command")
#parser.add_argument('-c') # case_id
#parser.add_argument('-i', action='append') # item_id
#parser.add_argument('-n') # num entries
#parser.add_argument('-y', '--why') # reason for removal
#parser.add_argument('-p') # password
#parser.add_argument('-r') # reverse entries
#parser.add_argument('-o') # owner
#parser.add_argument('-g') # creator
#action = parser.parse_args()

AES_KEY = b"R0chLi4uLi4uLi4="

parser = argparse.ArgumentParser()

# Define subparsers for different commands
subparsers = parser.add_subparsers(dest="command")

# 'add' command
ad_parser = subparsers.add_parser("add")
ad_parser.add_argument('-c', type=str, help="Case ID")
ad_parser.add_argument('-i', action='append', required=True, help="Item ID")
ad_parser.add_argument('-g', type=str, required=True, help="Creator")
ad_parser.add_argument('-p', type=str, required=True, help="Password")

# 'checkout' command
checkout_parser = subparsers.add_parser("checkout")
checkout_parser.add_argument('-i', type=str, required=True, help="Item ID")
checkout_parser.add_argument('-p', type=str, required=True, help="Password")

# 'checkin' command
checkin_parser = subparsers.add_parser("checkin")
checkin_parser.add_argument('-i', type=str, required=True, help="Item ID")
checkin_parser.add_argument('-p', type=str, required=True, help="Password")

# 'show' command
show_parser = subparsers.add_parser("show")
show_subparsers = show_parser.add_subparsers(dest="show_command")

# 'show cases' sub-command
show_cases_parser = show_subparsers.add_parser("cases")

# 'show items' sub-command
show_items_parser = show_subparsers.add_parser("items")
show_items_parser.add_argument('-c', type=str, required=True, help="Case ID")

# 'show history' sub-command
show_history_parser = show_subparsers.add_parser("history")
show_history_parser.add_argument('-c', type=str, help="Case ID")
show_history_parser.add_argument('-i', type=str, help="Item ID")
show_history_parser.add_argument('-n', type=int, help="Number of entries")
show_history_parser.add_argument('-r', action='store_true', help="Reverse entries")
show_history_parser.add_argument('-p', type=str, required=True, help="Password")

# 'remove' command
remove_parser = subparsers.add_parser("remove")
remove_parser.add_argument('-i', type=str, required=True, help="Item ID")
remove_parser.add_argument('-y', type=str, required=True, help="Reason")
remove_parser.add_argument('-p', type=str, required=True, help="Password (creator's)")

# 'init' command
init_parser = subparsers.add_parser("init")

# 'verify' command
verify_parser = subparsers.add_parser("verify")

args = parser.parse_args()

# get the file path from the environment variable
#file_path = os.getenv('BCHOC_FILE_PATH')

#struct format string, need to add data field dynamically
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
    #length is known to be 14 for genesis block, so 14 bytes added for data
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

def countblocks(file_path):
    numblocks = 0
    with open(file_path, "rb") as file:
        while True:
            partialblock = struct.Struct(structformat)
            block_data = file.read(partialblock.size)
            if not block_data:
                break  # Reached end of file
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength = partialblock.unpack(block_data)
            file.seek(partialblock.size + dlength)
            numblocks += 1
        return numblocks

def get_deepest_previous_hash(file_path):
    with open(file_path, "rb") as file:
        while True:
            partialblock = struct.Struct(structformat)
            block_data = file.read(partialblock.size)
            if not block_data:
                break  # Reached end of file
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength = partialblock.unpack(block_data)
            #dlength = struct.unpack("I", block_data[-4:])[0]
            data = file.read(dlength)
            catstring = prev_hash + struct.pack("d", timestamp) + case_id + evidence_id + state + creator + owner + struct.pack("I", dlength) + data
            file.seek(partialblock.size + dlength)
        hashed = hashlib.sha256(catstring).hexdigest()
        return hashed

def isotime():
    currenttime = datetime.datetime.utcnow()
    iso = currenttime.isoformat()
    print(iso)
    return iso
    
def floattime():
    fltime = float(time.time())
    return fltime
    
def encrypt_aes_ecb(plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def decrypt_case_id(id_hex):
    id_bytes = bytes.fromhex(id_hex)
    decrypted_id_bytes = decrypt_aes_ecb(AES_KEY, id_bytes)
    id_uuid = UUID(bytes=decrypted_id_bytes)
    return id_uuid

#add a case
def addcase(file_path):
    for i in args.i:
        if countblocks(file_path) == 1:
            with open(file_path, "ab") as file:
                dynamicformat = structformat + " 0s"
                block_format = struct.Struct(dynamicformat)
                previoushash = b"\0"*32
                uuidint = UUID(args.c).int
                uuidbytes = uuidint.to_bytes(16, byteorder='big')
                case_id = encrypt_aes_ecb(uuidbytes)
                evidence_int = int(i)
                hexid = evidence_int.to_bytes(16)
                evidence_id = encrypt_aes_ecb(hexid)
                state = b"CHECKEDIN\0\0\0"
                d_length = 0
                data = b""
                owner = b"AAAA\0\0\0\0\0\0\0\0\0\0\0\0"
         
                # Pack data into binary format
                block_data = block_format.pack(
                    previoushash, floattime(), case_id, evidence_id,
                    state, args.g.encode('utf-8'), owner, d_length, data
                )
                file.write(block_data)
        else:
            with open(file_path, "ab") as file:
                print(countblocks(file_path))
                dynamicformat = structformat + " 0s"
                block_format = struct.Struct(dynamicformat)
                previoushash = get_deepest_previous_hash(file_path)
                uuidint = UUID(args.c).int
                uuidbytes = uuidint.to_bytes(16, byteorder='big')
                case_id = encrypt_aes_ecb(uuidbytes)
                evidence_int = int(i)
                hexid = evidence_int.to_bytes(16)
                evidence_id = encrypt_aes_ecb(hexid)
                state = b"CHECKEDIN\0\0\0"
                d_length = 0
                data = b""
                owner = b"AAAA\0\0\0\0\0\0\0\0\0\0\0\0"
                # Pack data into binary format
                block_data = block_format.pack(
                    previoushash.encode('utf-8'), floattime(), case_id, evidence_id,
                    state, args.g.encode('utf-8'), owner, d_length, data
                )
                file.write(block_data)

def main():
    file_path = get_file_path()
    if not check_existing_blocks(file_path):
        create_genesis_block(file_path)
        print("genesis block created.")
    else:
        print("blockchain already exists.")
    if args.command == "add":
        addcase(file_path)

if __name__ == "__main__":
    main()
