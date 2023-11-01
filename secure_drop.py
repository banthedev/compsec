import os
import json
import getpass
import crypt

config_file = "./passwd.json"


def main():
    if not os.path.exists(config_file):
        print("No users are registered with this client.")
        res = input("Would you like to register a new user? (y/n): ")
        if res == "N" or res == 'n':
            print("Exiting.")
            exit()
        elif res == 'Y' or res == 'y':
            register_user()
            exit()
    else:
        log_in(3)

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


def store_user(name, email, hashed_password):

    data = {
        "name": name,
        "email": email,
        "password": hashed_password
    }

    json.dump(data, open(config_file, "w"), sort_keys=True, indent=4)


def register_user():
    print("\n")
    name = input("Enter full name: ")
    email = input("Enter full email: ")
    password = getpass.getpass("Enter full password: ")
    re_password = getpass.getpass("Re-type password: ")

    print("\n")
    if password != re_password:
        print("Passwords do not match.\nUser not registered.")
    else:
        print("Passwords match.")

        # crate a shah512 hash of the password
        salt = crypt.mksalt(crypt.METHOD_SHA512)

        # create the hash using the salt
        hash = crypt.crypt(password, salt)

        # store the new user and hashed password in the db
        store_user(name, email, hash)
        print("User registered.")


def print_help():
    print("\t\"add\"\t-> Add a new contact")
    print("\t\"list\"\t-> List all online contacts")
    print("\t\"send\"\t-> Transfer file to contact")
    print("\t\"exit\"\t-> Exit SecureDrop")


if __name__ == "__main__":
    main()
