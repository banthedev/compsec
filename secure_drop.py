import os
import json
import getpass


config_file = "./config.json"


def main():
    if not os.path.exists(config_file):
        print("No users are registered with this client.")
        res = input("Would you like to register a new user? (y/n): ")
        if res == "N" or res == 'n':
            print("Exiting.")
            exit()
        elif res == 'Y' or res == 'y':
            register_user()
    else:
        log_in()


def log_in():
    email = input("Enter email address: ")
    password = getpass.getpass("Enter password: ")

    obj = json.load(open(config_file, "r"))
    if obj["email"] == email and obj["password"] == password:
        print("\nWelcome to SecureDrop.")
        print("\nType \"help\" for commands.")
        return True
    else:
        print("\nUsername and password not verified.")
    return False


def store_user(name, email, password):

    data = {
        "name": name,
        "email": email,
        "password": password
    }

    json.dump(data, open(config_file, "w"), sort_keys=True, indent=4)
    return True


def register_user():
    print("\n")
    name = input("Enter full name: ")
    email = input("Enter full email: ")
    password = getpass.getpass("Enter full password: ")
    re_password = getpass.getpass("Re-type password: ")

    print("\n")
    if password != re_password:
        print("Passwords do not match.\nUser not registered.")
        return False
    else:
        print("Passwords match.")
        store_user(name, email, password)
        print("User registered.")
        return True


if __name__ == "__main__":
    main()
