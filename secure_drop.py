import os
import json
import getpass
import crypt

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

config_file = "./.config/SecureDrop/config.json"


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

    print("Exiting SecureDrop.")

# returns true if the user has sucessfully logged in
# returns false if there was an error


def log_in(n_attempts=0):
    email = input("Enter email address: ")
    password = getpass.getpass("Enter password: ")

    obj = json.load(open(config_file, "r"))

    # get the hashed password from the db
    stored_hash = obj["password"]

    # extract the salt from that hash
    salt = stored_hash[:stored_hash.index("$", 3) + 1]

    # create a hash of the password the user entered,
    # using the stored salt from the registration.
    new_hash = crypt.crypt(password, salt)

    # check if the user has sucessfully logged in.
    if obj["email"] == email and stored_hash == new_hash:
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
            return log_in(n_attempts)


def register_user():
    print("No users are registered with this client.")
    res = input("Would you like to register a new user? (y/n): ")

    # exit if the user doesn't want to register
    if res != 'Y' and res != 'y':
        print("Unknown Input. Exiting SecureDrop.")
        exit()

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

    # crate a shah512 hash of the password
    salt = crypt.mksalt(crypt.METHOD_SHA512)

    # create the hash using the salt
    hash = crypt.crypt(password, salt)

    # store the new user and hashed password in the db
    data = {
        "name": name,
        "email": email,
        "password": hash
    }

    # create the path for the DB
    os.makedirs(os.path.dirname(config_file))

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


def print_help():
    print("\t\"add\"\t-> Add a new contact")
    print("\t\"list\"\t-> List all online contacts")
    print("\t\"send\"\t-> Transfer file to contact")
    print("\t\"exit\"\t-> Exit SecureDrop")


if __name__ == "__main__":
    main()
