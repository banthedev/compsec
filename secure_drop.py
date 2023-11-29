import os
import json
import getpass
import crypt
import base64
import socket

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

config_file = "./.config/SecureDrop/config.json"
encryption_key_file = "./.config/SecureDrop/key.json"


def main():
    # If the config file does not exist,
    if not os.path.exists(config_file):
        register_user()
        exit()
    else:
        log_in(3)

    # At this point, the shell is opened.

    cmd = ""
    while cmd != "exit":
        cmd = input("secure_drop> ")

        if cmd == "help":
            print_help()

        elif cmd == "add":
            add_contact()

        elif cmd == "list":
            list_contacts()

    print("Exiting SecureDrop.")

# returns true if the user has sucessfully logged in
# returns false if there was an error


def log_in(n_attempts=0):
    email = input("Enter email address: ")
    password = getpass.getpass("Enter password: ")

    obj = json.load(open(config_file, "r"))["data"]

    # get the hashed password from the db
    stored_hash = obj["password"]

    # extract the salt from that hash
    salt = stored_hash[:stored_hash.index("$", 3) + 1]

    # create a hash of the password the user entered,
    # using the stored salt from the registration.
    new_hash = crypt.crypt(password, salt)

    # decrypt the name, email from the database
    encryption_key = get_aes_encryption_key()
    decrypted_email = decrypt_data(
        obj["eiv"], obj["email"], encryption_key)

    # check if the user has sucessfully logged in.
    if decrypted_email == email and stored_hash == new_hash:
        print("\nWelcome to SecureDrop.")
        print("\nType \"help\" for commands.")
    else:
        # The user failed login.
        print("\nUsername and password not verified.")
        n_attempts -= 1

        # check if the user has used up all their login attempts for this session
        if n_attempts == 0:
            print("You have used the maximum number of attempts. Exiting.")
            exit()
        else:
            # try again
            print(f"You have {n_attempts} attempts remaining.")
            log_in(n_attempts)


def register_user():
    print("No users are registered with this client.")
    res = input("Would you like to register a new user? (y/n): ")

    # exit if the user doesn't want to register
    if res != 'Y' and res != 'y':
        print("Unknown Input. Exiting SecureDrop.")
        exit()

    # create the path for the DB
    os.makedirs(os.path.dirname(config_file))

    print("\n")
    name = input("Enter full name: ")
    email = input("Enter full email: ")
    password = getpass.getpass("Enter full password: ")
    re_password = getpass.getpass("Re-type password: ")

    print("\n")
    if password != re_password:
        print("Passwords do not match.\nUser not registered.")
        print("Exiting SecureDrop.")
        exit()

    # the passwords are equal
    print("Passwords match.")

    # create a shah512 hash of the password
    salt = crypt.mksalt(crypt.METHOD_SHA512)

    # create the hash using the salt
    hash = crypt.crypt(password, salt)

    # Now, we create an AES encryption key to use for storing names/emails.
    encryption_key = get_random_bytes(16)
    encryption_key = base64.b64encode(encryption_key).decode('utf-8')
    json.dump({"key": encryption_key}, open(encryption_key_file, "w"),
              sort_keys=True, indent=4)
    encryption_key = base64.b64decode(encryption_key)

    # store the new user and hashed password in the db
    niv, encrypted_name = encrypt_data(name, encryption_key)
    eiv, encrypted_email = encrypt_data(email, encryption_key)
    data = {
        "data": {"name": encrypted_name,
                 "niv": niv,
                 "email": encrypted_email,
                 "eiv": eiv,
                 "password": hash,
                 "contacts": []
                 }}

    json.dump(data, open(config_file, "w"),
              sort_keys=True, indent=4)

    # now, create the public and private key

    # generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # get the public key from the private key
    public_key = private_key.public_key()

    # serialize the private key
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # serialize the public key
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save the keys to files
    with open('./.config/SecureDrop/private_key', 'wb') as f:
        f.write(private_key_pem)

    with open('./.config/SecureDrop/public_key', 'wb') as f:
        f.write(public_key_pem)

    print("User registered.")


def add_contact():
    encryption_key = get_aes_encryption_key()

    # prompt for input
    name = input("\nEnter full name: ")
    email = input("Enter email: ")

    obj = json.load(open(config_file, "r"))

    # encrypt the data
    niv, encrypted_name = encrypt_data(name, encryption_key)
    eiv, encrypted_email = encrypt_data(email, encryption_key)
    obj["data"]["contacts"].append({
        "name": encrypted_name,
        "niv":  niv,
        "email": encrypted_email,
        "eiv": eiv
    })

    json.dump(obj, open(config_file, "w"),
              sort_keys=True, indent=4)

    print("Contact Added.")

def list_contacts():
    contacts = json.load(open(config_file, "r"))["data"]["contacts"]
    network_key = get_aes_encryption_key()
    for contact in contacts:
        name, email = decrypt_contact(contact)
        # An example host and port
        host = "localhost"
        port = 2022
        if is_contact_online(email, host, port, network_key):
            print(f'\t * {name} <{email}> - Online')
        else:
            print(f'\t * {name} <{email}> - Offline')

# Symmetric encryption to encrypt email before being sent over the network
def encrypt_network_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def is_contact_online(email, host, port, network_key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Timeout for the socket operation
            s.connect((host, port))

            cncrypted_email = encrypt_network_data(email, network_key)
            s.sendall(cncrypted_email)
            data = s.recv(1024).decode()
            return data == "online"
    except socket.error:
        return False


def print_help():
    print("\t\"add\"\t-> Add a new contact")
    print("\t\"list\"\t-> List all online contacts")
    print("\t\"send\"\t-> Transfer file to contact")
    print("\t\"exit\"\t-> Exit SecureDrop")


def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct


def decrypt_data(iv, ct, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


def decrypt_contact(contact):
    encryption_key = get_aes_encryption_key()
    decrypted_name = decrypt_data(
        contact["niv"], contact["name"], encryption_key)
    decrypted_email = decrypt_data(
        contact["eiv"], contact["email"], encryption_key)
    return decrypted_name, decrypted_email


def get_aes_encryption_key():
    encryption_key = json.load(open(encryption_key_file, "r"))["key"]
    return base64.b64decode(encryption_key)


if __name__ == "__main__":
    main()
