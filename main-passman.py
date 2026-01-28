import os
import json
import sys
import getpass
from os.path import isfile
from hashlib import sha256
from termcolor import colored
from halo import Halo

from modules.encryption import DataManip
from modules.exceptions import UserExits, PasswordFileDoesNotExist 
from modules.menu import Manager 

def start(obj: DataManip):
    if os.path.isfile("db/masterpassword.json"):
        with open("db/masterpassword.json", 'r') as jsondata:
            jfile = json.load(jsondata)

        stored_master_hash = jfile["Master"] # load the saved hashed password
        master_password = getpass.getpass(colored("Enter Master Password: ", "green"))

        # compare the two hashes of input and stored master password
        spinner = Halo(text=colored("Unlocking...", "green"), spinner=obj.dots_, color="green")
        if sha256(master_password.encode('utf-8')).hexdigest() == stored_master_hash:
            print(colored(f"{obj.checkmark_} Unlocked successfully !! :)\n", "green"))
            # create instance of manager class
            menu = Manager(obj, "db/passwords.json", "db/masterpassword.json", master_password)
            try:
                menu.begin()
            except UserExits:
                exit_program()
            except PasswordFileDoesNotExist:
                print(colored(f"{obj.crossmark_} Password database does not exist :( Try adding a password", "red"))
        else:
            print(colored(f"{obj.crossmark_} Incorrect Master Password !! :(\n", "red"))
            return start(obj)
    else: # first time running program; create master password
        try:
            os.mkdir("db/")
        except FileExistsError:
            pass

        print(colored("You have to create a master password !! :) Be careful not to lose it as it is unrecoverable.", "magenta"))
        master_password = getpass.getpass("Create a master password: ")
        second_input = getpass.getpass("Verify your master pasword: ")

        if master_password == second_input:
            spinner = Halo(text=colored("initializing base...", "green"), color="green", spinner=obj.dots_)
            hash_master = sha256(master_password.encode("utf-8")).hexdigest()
            jfile = {"Master": {}}
            jfile["Master"] = hash_master
            with open("db/masterpassword.json", 'w') as jsondata:
                json.dump(jfile, jsondata, sort_keys=True, indent=4)
            spinner.stop()
            print(colored(f"{obj.checkmark_} Thank you! Restart the program and enter your master password to begin.", "magenta"))
        else:
            print(colored(f"{obj.x_mark_} Passwords do not match </3 Please try again", "red"))
            return start(obj)
        
def exit_program():
    print(colored("\nExiting Chloe's Password Manager... Goodbye ! :)\n", "magenta"))
    sys.exit()


if __name__ == "__main__":
    obj = DataManip()
    start(obj)