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



# Define the VALID_PASSWORDS dictionary dynamically
#passwords = {key: os.environ.get(f"BCHOC_PASSWORD_{key}", None) for key in PASSWORD_KEYS}


# get the file path from the environment variable
def get_file_path():
    # file_path = os.getenv("BCHOC_FILE_PATH")
    # if file_path:
    #     return file_path
    # else:
    #     exit(1)
        #replace with your local path for testing
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        blockchain_folder_path = os.path.join(desktop_path, "Blockchain")
        if not os.path.exists(blockchain_folder_path):
            os.makedirs(blockchain_folder_path)  # Create the folder if it doesn't exist
        return os.path.join(blockchain_folder_path, "blockchain.dat")

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

# chcecks for the genesis block
def check_genesis_block(file_path):
    if not os.path.isfile(file_path):
        create_genesis_block(file_path)
        return False
    else:
        with open(file_path, "rb") as file:
            # Read the first block data
            block_data = file.read(struct.calcsize(structformat))
            if not block_data:
                return False  # No blocks found
            else:
                # Unpack block data
                prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength = struct.unpack(structformat, block_data)
                # Check if it's the genesis block
                if state.strip(b'\x00') == b"INITIAL":
                    return True
                else:
                    return False

def countblocks(file_path):
    numblocks = 0
    currentbyte = 0
    with open(file_path, "rb") as file:
        if check_genesis_block(file_path):
            numblocks += 1
        else:
            return numblocks
        partialblock = struct.Struct(structformat)
        file.seek(partialblock.size + 14)
        currentbyte += partialblock.size + 14
        block_data = file.read(partialblock.size)
        while True:
            if not block_data:
                break  # Reached end of file
            numblocks += 1
            currentbyte += partialblock.size
            file.seek(currentbyte)
            block_data = file.read(partialblock.size)
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

def isotime(timestamp):
    dtobj = datetime.datetime.utcfromtimestamp(timestamp)
    iso = dtobj.isoformat()
    return iso
    
def floattime():
    fltime = float(time.time())
    return fltime

import binascii
def encrypt_aes_ecb(plaintext):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    ciphertext_hex = binascii.hexlify(ciphertext)
    
    return ciphertext_hex

def decrypt_aes_ecb(ciphertext_hex):
    ciphertext = binascii.unhexlify(ciphertext_hex)
    backend = default_backend()
    cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

#add a case
def addcase(file_path):

    # if args.p != CREATOR_PASSWORD:
    #     exit("incorrect password")
    

    existing_item_ids = set()

    # read item ids from chain
    with open(file_path, "rb") as file:
        while True:
            partialblock = struct.Struct(structformat)
            block_data = file.read(partialblock.size)
            if not block_data:
                break  # Reached end of file
            _, _, _, evidence_id, _, _, _, dlength = partialblock.unpack(block_data)
            file.seek(partialblock.size + dlength)
            existing_item_ids.add(evidence_id)

    # check for existing item id
    for i in args.i:
        evidence_id = encrypt_aes_ecb(int(i).to_bytes(16, byteorder='big'))
        if evidence_id in existing_item_ids:
            exit(f"Item with ID {i} already exists in the blockchain.")
            return
        
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
                hexid = evidence_int.to_bytes(16, byteorder='big')
                evidence_id = encrypt_aes_ecb(hexid)
                state = b"CHECKEDIN\0\0\0"
                d_length = 0
                data = b""
                owner = b"\0\0\0\0\0\0\0\0\0\0\0\0"
         
                # Pack data into binary format
                block_data = block_format.pack(
                    previoushash, floattime(), case_id, evidence_id,
                    state, args.g.encode('utf-8'), owner, d_length, data
                )

                file.write(block_data)
                print("Added item:", i)
                print("Status: CHECKEDIN")
                #isotime()
        else:
            with open(file_path, "ab") as file:
                dynamicformat = structformat + " 0s"
                block_format = struct.Struct(dynamicformat)
                previoushash = get_deepest_previous_hash(file_path)
                uuidint = UUID(args.c).int
                uuidbytes = uuidint.to_bytes(16, byteorder='big')
                case_id = encrypt_aes_ecb(uuidbytes)
                evidence_int = int(i)
                hexid = evidence_int.to_bytes(16, byteorder='big')
                evidence_id = encrypt_aes_ecb(hexid)
                state = b"CHECKEDIN\0\0\0"
                d_length = 0
                data = b""
                owner = b"\0\0\0\0\0\0\0\0\0\0\0\0"
                # Pack data into binary format
                block_data = block_format.pack(
                    previoushash.encode('utf-8'), floattime(), case_id, evidence_id,
                    state, args.g.encode('utf-8'), owner, d_length, data
                )

                file.write(block_data)
                print("Added item:", i)
                print("Status: CHECKEDIN")
                #isotime()

def parseblocks(file_path, parsetype, matchcase = "", matchevi = ""):
    currentbyte = 0
    blockstruct = struct.Struct(structformat)
    blocks = []
    with open(file_path, "rb") as file:
        file.seek(blockstruct.size + 14)
        currentbyte += blockstruct.size + 14
        block_data = file.read(blockstruct.size)
        while True:
            if not block_data:
                break  # Reached end of file
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength = blockstruct.unpack(block_data)
            if parsetype == "MatchBoth":
                decrypteduuid = decrypt_aes_ecb(case_id)
                cintuuid = int.from_bytes(decrypteduuid, byteorder='big')
                caseuuid = UUID(int=cintuuid)
                decryptedevi = decrypt_aes_ecb(evidence_id)
                eint = int.from_bytes(decryptedevi, byteorder = 'big')
                if str(caseuuid) == matchcase and str(eint) == matchevi:
                    blocks.append([prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength])
            elif parsetype == "MatchCase":
                decrypteduuid = decrypt_aes_ecb(case_id)
                cintuuid = int.from_bytes(decrypteduuid, byteorder='big')
                caseuuid = UUID(int=cintuuid)
                if str(caseuuid) == matchcase:
                    blocks.append([prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength])
            elif parsetype == "MatchEvi":
                decryptedevi = decrypt_aes_ecb(evidence_id)
                eint = int.from_bytes(decryptedevi, byteorder = 'big')
                if str(eint) == matchevi:
                    blocks.append([prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength])
            currentbyte += blockstruct.size
            file.seek(currentbyte)
            block_data = file.read(blockstruct.size)
        if not blocks:
           exit("Blocks not found")
        return blocks

def history(file_path):
    reverse = False
    caselist = []
    if not check_genesis_block(file_path):
        exit("no genesis block")
    if args.p not in passwordlist:
        exit("invalid password")
    if args.r:
        reverse = True
    if args.c and args.i:
        caselist = parseblocks(file_path, "MatchBoth", args.c, args.i)
    elif args.c:
        caselist = parseblocks(file_path,"MatchCase", args.c)
    elif args.i:
        caselist = parseblocks(file_path, "MatchEvi", "", args.i)
    if args.n:
        print(countblocks(file_path))
    if caselist:
        if not reverse:
            for c in caselist:
                decrypteduuid = decrypt_aes_ecb(c[2])
                cintuuid = int.from_bytes(decrypteduuid, byteorder='big')
                caseuuid = UUID(int=cintuuid)
                print("Case: " + str(caseuuid))
                decryptedevi = decrypt_aes_ecb(c[3])
                eint = int.from_bytes(decryptedevi, byteorder = 'big')
                print("Item: " + str(eint))
                print("State: " + c[4].decode('utf-8'))
                print("Time: " + isotime(c[1]) + "Z\n")
                
        else:
            caselist.reverse()
            for c in caselist:
                decrypteduuid = decrypt_aes_ecb(c[2])
                cintuuid = int.from_bytes(decrypteduuid, byteorder='big')
                caseuuid = UUID(int=cintuuid)
                print("Case: " + str(caseuuid))
                decryptedevi = decrypt_aes_ecb(c[3])
                eint = int.from_bytes(decryptedevi, byteorder = 'big')
                print("Item: " + str(eint))
                print("State: " + c[4].decode('utf-8'))
                print("Time: " + isotime(c[1]) + "Z")
                print("\n")

def showcases(file_path):
    caselist = parseblocks(file_path, "GetCases")
    for c in caselist:
        decrypteduuid = decrypt_aes_ecb(c)
        cintuuid = int.from_bytes(decrypteduuid, byteorder='big')
        caseuuid = UUID(int=cintuuid)
        print(str(caseuuid) + "\n")

def showitems(file_path):
    itemlist = parseblocks(file_path, "GetItems", args.c)
    for i in itemlist:
        decryptedevi = decrypt_aes_ecb(i)
        eint = int.from_bytes(decryptedevi, byteorder = 'big')
        print(str(eint) + "\n")
def removecase(file_path):
    item_id = args.i
    reason = args.y
    password = args.p

    if not check_existing_blocks(file_path):
        print("Blockchain file not found.")
        return

    item_exists = False
    creator_password_matched = False
    with open(file_path, "rb") as file:
        while True:
            partialblock = struct.Struct(structformat)
            block_data = file.read(partialblock.size)
            if not block_data:
                break
            _, _, _, evidence_id, state, creator, _, dlength = partialblock.unpack(block_data)
            file.seek(partialblock.size + dlength)
            decrypted_evidence_id = decrypt_aes_ecb(evidence_id)
            if decrypted_evidence_id == int(item_id).to_bytes(16, byteorder='big'):
                item_exists = True
                if password == CREATOR_PASSWORD:
                    creator_password_matched = True
                break

    if not item_exists:
        exit(f"Item with ID {item_id} does not exist in the blockchain.")
        return
    elif not creator_password_matched:
        exit("Password is incorrect.")
        return

    if reason == "DISPOSED" or reason == "DESTROYED":
        state = b"DISPOSED\0\0\0\0\0\0\0\0\0\0\0"
    elif reason == "RELEASED":
        state = b"RELEASED\0\0\0\0\0\0\0\0\0\0\0"
        if not args.o:
            print("For RELEASED reason, '-o' option must be provided.")
            return
    else:
        exit("Invalid reason provided.")
        return

    with open(file_path, "rb") as file:
        previous_hash = get_deepest_previous_hash(file_path)
    uuid_int = UUID(args.c).int
    case_id = encrypt_aes_ecb(uuid_int.to_bytes(16, byteorder='big'))
    evidence_id = encrypt_aes_ecb(int(item_id).to_bytes(16, byteorder='big'))
    data_length = len(reason.encode('utf-8'))
    data = reason.encode('utf-8')
    owner = b"\0\0\0\0\0\0\0\0\0\0\0\0"

    block_format = struct.Struct(structformat + " 0s")
    block_data = block_format.pack(
        previous_hash.encode('utf-8'), floattime(), case_id, evidence_id,
        state, args.g.encode('utf-8'), owner, data_length, data
    )

    with open(file_path, "ab") as file:
        file.write(block_data)

    print("Item removed:", item_id)
    print("Reason:", reason)
    print("Time of action:", isotime())



def checkin(file_path):
    item_id = args.i

    # Check if the blockchain file exists
    # if not check_existing_blocks(file_path):
    #     print("Blockchain file not found.")
    #     return

    # Check if the provided item ID exists in the blockchain
    item_exists = False
    with open(file_path, "rb") as file:
        while True:
            partialblock = struct.Struct(structformat)
            block_data = file.read(partialblock.size)
            if not block_data:
                exit("Reached end of file.")
                break  # Reached end of file
            
            # Unpack block data into individual fields
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength = partialblock.unpack(block_data)

            #Print each section of information
            print("Previous Hash:", prev_hash)
            print("Timestamp:", timestamp)
            print("Case ID:", case_id)
            print("Evidence ID (Encrypted):", evidence_id)
            decrypted_evidence_id = decrypt_aes_ecb(evidence_id)
            print("Evidence ID (Decrypted):", int.from_bytes(decrypted_evidence_id, byteorder='big'))
            print("State:", state)
            print("Creator:", creator)
            print("Owner:", owner)
            print("Data Length:", dlength)

            # Seek to the next block
            file.seek(partialblock.size + dlength)

            # Check if the provided item ID matches the decrypted evidence ID
            print()
            print()
            print(int.from_bytes(decrypted_evidence_id, byteorder='big'))
            print(int(item_id))
            if int.from_bytes(decrypted_evidence_id, byteorder='big') == int(item_id):
                # identify that an id exists in the chain
                item_exists = True
                mostRecentCaseID = case_id
                mostRecentCreator = creator
                # set the most recent state of that item in the chain
                MostRecentstate = state
                #break

    print()
    print("done parsing")
    print()

    # Check if the item is already checked in
    if not item_exists:
        exit(f"Item with ID {item_id} does not exist in the blockchain.")
    elif MostRecentstate.strip(b'\x00') == b"CHECKEDIN":
        exit("item is checked in already")
    # elif args.p not in passwordlist:
    #     exit("invalid password")
    # Prepare data for the new block

    with open(file_path, "ab") as file:
        dynamicformat = structformat + " 0s"
        block_format = struct.Struct(dynamicformat)
        previoushash = get_deepest_previous_hash(file_path)
        uuidint = UUID(mostRecentCaseID)
        uuidbytes = uuidint.to_bytes(16, byteorder='big')
        case_id = encrypt_aes_ecb(uuidbytes)
        evidence_int = int(item_id)
        hexid = evidence_int.to_bytes(16, byteorder='big')
        evidence_id = encrypt_aes_ecb(hexid)
        state = b"CHECKEDIN\0\0\0"
        d_length = 0
        data = b""
        owner = b"\0\0\0\0\0\0\0\0\0\0\0\0" # Assuming the owner is set to all zeros for now

        # Pack data into binary format
        block_format = struct.Struct(structformat + " 0s")
        block_data = block_format.pack(
            previoushash.encode('utf-8'), floattime(), case_id, evidence_id,
            state, creator, owner, d_length, data
            )

            # Append the new block to the blockchain file
        
        file.write(block_data)

        # Print checkout details
    print("Case:", int.from_bytes(decrypted_evidence_id, byteorder='big'))
    print("Checked out item:", item_id)
    print("Status: CHECKEDIN")
    #print("Time of action:", isotime())


def checkout(file_path):
    item_id = args.i

    # Check if the blockchain file exists
    # if not check_existing_blocks(file_path):
    #     print("Blockchain file not found.")
    #     return

    # Check if the provided item ID exists in the blockchain
    item_exists = False
    with open(file_path, "rb") as file:
        while True:
            partialblock = struct.Struct(structformat)
            block_data = file.read(partialblock.size)
            if not block_data:
                exit("Reached end of file.")
                break  # Reached end of file
            
            # Unpack block data into individual fields
            prev_hash, timestamp, case_id, evidence_id, state, creator, owner, dlength = partialblock.unpack(block_data)

            #Print each section of information
            print("Previous Hash:", prev_hash)
            print("Timestamp:", timestamp)
            print("Case ID:", case_id)
            print("Evidence ID (Encrypted):", evidence_id)
            decrypted_evidence_id = decrypt_aes_ecb(evidence_id)
            print("Evidence ID (Decrypted):", int.from_bytes(decrypted_evidence_id, byteorder='big'))
            print("State:", state)
            print("Creator:", creator)
            print("Owner:", owner)
            print("Data Length:", dlength)

            # Seek to the next block
            file.seek(partialblock.size + dlength)

            # Check if the provided item ID matches the decrypted evidence ID
            print()
            print()
            print(int.from_bytes(decrypted_evidence_id, byteorder='big'))
            print(int(item_id))
            if int.from_bytes(decrypted_evidence_id, byteorder='big') == int(item_id):
                # identify that an id exists in the chain
                item_exists = True
                mostRecentCaseID = case_id
                mostRecentCreator = creator
                # set the most recent state of that item in the chain
                MostRecentstate = state
                #break

    print()
    print("done parsing")
    print()

    # Check if the item is already checked in
    if not item_exists:
        exit(f"Item with ID {item_id} does not exist in the blockchain.")
    elif MostRecentstate.strip(b'\x00') == b"CHECKEDOUT":
        exit("item is checked in already")
    # elif args.p not in passwordlist:
    #     exit("invalid password")
    # Prepare data for the new block

    with open(file_path, "ab") as file:
        dynamicformat = structformat + " 0s"
        block_format = struct.Struct(dynamicformat)
        previoushash = get_deepest_previous_hash(file_path)
        uuidint = UUID(mostRecentCaseID)
        uuidbytes = uuidint.to_bytes(16, byteorder='big')
        case_id = encrypt_aes_ecb(uuidbytes)
        evidence_int = int(item_id)
        hexid = evidence_int.to_bytes(16, byteorder='big')
        evidence_id = encrypt_aes_ecb(hexid)
        state = b"CHECKEDOUT\0\0\0"
        d_length = 0
        data = b""
        owner = b"\0\0\0\0\0\0\0\0\0\0\0\0" # Assuming the owner is set to all zeros for now

        # Pack data into binary format
        block_format = struct.Struct(structformat + " 0s")
        block_data = block_format.pack(
            previoushash.encode('utf-8'), floattime(), case_id, evidence_id,
            state, creator, owner, d_length, data
            )

            # Append the new block to the blockchain file
        
        file.write(block_data)

        # Print checkout details
    print("Case:", int.from_bytes(decrypted_evidence_id, byteorder='big'))
    print("Checked out item:", item_id)
    print("Status: CHECKEDOUT")



POLICE_PASSWORD = os.environ.get("BCHOC_PASSWORD_POLICE")
LAWYER_PASSWORD = os.environ.get("BCHOC_PASSWORD_LAWYER")
ANALYST_PASSWORD = os.environ.get("BCHOC_PASSWORD_ANALYST")
EXECUTIVE_PASSWORD = os.environ.get("BCHOC_PASSWORD_EXECUTIVE")
CREATOR_PASSWORD = os.environ.get("BCHOC_PASSWORD_CREATOR")
passwordlist = [POLICE_PASSWORD, LAWYER_PASSWORD, ANALYST_PASSWORD, EXECUTIVE_PASSWORD, CREATOR_PASSWORD]


def main():
    file_path = get_file_path()

    
    
    if args.command == "init":
        if check_genesis_block(file_path):
            print("Blockchain file found with INITIAL block.")
        else:
            print("Blockchain file not found. Created INITIAL block.")
    elif args.command == "add":
        # if the genesis block doesn't exist when a case is attempted to be added
        # it might have to invoke an error exit, but for now just create it then add
        # gotta check project doc
        if not check_existing_blocks(file_path):
            create_genesis_block(file_path)
            addcase(file_path)
        else:
            addcase(file_path)
    elif args.command == "remove":
        if not check_existing_blocks(file_path):
            print("Error: No blocks found. Please add a block before removing.")
            sys.exit(1)
        removecase(file_path)
    elif args.command == "checkin":
        checkin(file_path)
    elif args.command == "checkout":
        checkout(file_path)
    elif args.command == "show":
        if args.show_command == "cases":
            showcases(file_path)
        elif args.show_command == "items":
            showitems(file_path)
        elif args.show_command == "history":
            history(file_path)

if __name__ == "__main__":
    main()
