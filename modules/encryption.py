import json
import string
import os
import random

from Crypto.Cipher import AES
from halo import Halo
from termcolor import colored

from modules.exceptions import *

# helper class for data manipulation and encryption/decryption
class DataManip:
    def __init__(self):
        self.dots_ = {"interval": 80, "frames": ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]}
        self.checkmark_ = "\u2713"
        self.crossmark_ = "\u2717"
        self.x_mark_ = "\u2717"
        self.specialChars_ = "!@#$%^&*()-_=+[]{}|;:,.<>?/`~"

    # saves password to database
    def __save_password(self, filename, data, nonce, website):
        spinner = Halo(text=colored("Saving password...", "green"), spinner=self.dots_, color="green")
        spinner.start()
        
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        # Create the file if it doesn't exist
        if not os.path.isfile(filename):
            with open(filename, 'w') as jsondata:
                json.dump({}, jsondata)
        
        try:
            with open(filename, 'r') as jsondata:
                jfile = json.load(jsondata)
            
            # Check if website already exists
            if website in jfile:
                jfile[website]["nonce"] = nonce
                jfile[website]["password"] = data
            else:
                jfile[website] = {}
                jfile[website]["nonce"] = nonce
                jfile[website]["password"] = data
            
            with open(filename, 'w') as jsondata:
                json.dump(jfile, jsondata, sort_keys=True, indent=4)
            
            spinner.stop()
            print(colored(f"{self.checkmark_} Password saved successfully !! :)", "green"))
            
        except Exception as e:
            spinner.stop()
            print(colored(f"{self.crossmark_} Error saving password: {e}", "red"))

    # encrypt data and save to file using master password
    def encrypt_data(self, filename, data, master_pass, website):
        concatenated_master = master_pass + "================"
        key = concatenated_master[:16].encode('utf-8')
        cipher = AES.new(key, AES.MODE_EAX)

        # can never be reused; will be converted back to bytes while decrypting but stored as hex since json doesn't support bytes
        nonce = cipher.nonce.hex()

        data_to_encrypt = data.encode('utf-8')
        encrypted_data = cipher.encrypt(data_to_encrypt).hex()

        self.__save_password(filename, encrypted_data, nonce, website)

    # returns a decrypted password as a string
    def decrypt_data(self, master_pass, website, filename):
        if os.path.isfile(filename):
            try:
                with open(filename, 'r') as jsondata:
                    jfile = json.load(jsondata)
                nonce = bytes.fromhex(jfile[website]["nonce"])
                password = bytes.fromhex(jfile[website]["password"])
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist
        # add extra chars to master password to make it 16 bytes long
        formatted_master_pass = master_pass + "================"
        master_pass_encoded = formatted_master_pass[:16].encode('utf-8')
        cipher = AES.new(master_pass_encoded, AES.MODE_EAX, nonce=nonce)
        plaintext_password = cipher.decrypt(password).decode('utf-8')
        return plaintext_password
    
    # generates a random, complex password
    def generate_password(self):
        password = []
        length = input(colored("Enter password length (at least 8): ", "cyan"))

        if length.lower().strip() == 'exit':
            raise UserExits
        elif length.strip() == "":
            raise EmptyField
        elif int(length) < 8:
            raise PasswordNotLongEnough
        else:
            # generating a password 
            spinner = Halo(text=colored("Generating password...", "green"), spinner=self.dots_, color="green")
            spinner.start()
            for i in range(0, int(length)):
                # choose a random character type
                password.append(random.choice(random.choice([string.ascii_lowercase, string.ascii_uppercase, string.digits, self.specialChars_])))
            finalPass = "".join(password)
            spinner.stop()
            return finalPass
    
    # loads a list of websites in database
    def list_passwords(self, filename):
        if os.path.isfile(filename):
            with open(filename, 'r') as jsondata:
                pass_list = json.load(jsondata)
            passwords_lst = ""
            for i in pass_list:
                passwords_lst += "--{}\n".format(i)

            if passwords_lst == "":
                raise PasswordFileIsEmpty
            else:
                return passwords_lst
        else:
            raise PasswordFileDoesNotExist
    
    # delete database/password file and contents
    def delete_db(self, filename, stored_master, entered_master):
        if os.path.isfile(filename):
            if stored_master == entered_master:
                # first clear the data
                spinner = Halo(text=colored("Deleting database...", "red"), spinner=self.dots_, color="red")
                spinner.start()
                jfile = {}
                with open(filename, 'w') as jdata:
                    json.dump(jfile, jdata)
                # then delete the file
                os.remove(filename)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
        else:
            raise PasswordFileDoesNotExist
    
    # deletes a single password entry from database
    def delete_password(self, filename, website):
        if os.path.isfile(filename):
            with open(filename, 'r') as jdata:
                jfile = json.load(jdata)
            try:
                jfile.pop(website)
                with open(filename, 'w') as jdata:
                    json.dump(jfile, jdata, sort_keys=True, indent=4)
            except KeyError:
                raise PasswordNotFound
        else:
            raise PasswordFileDoesNotExist
    
    # deletes all data including master password and passwords database
    def delete_all_data(self, filename, master_file, stored_master, entered_master):
        if os.path.isfile(master_file) and os.path.isfile(filename): # both files exist
            if stored_master == entered_master:
                spinner = Halo(text=colored("Deleting all data...", "red"), spinner=self.dots_, color="red")
                spinner.start()
                # first clear data
                jfile = {}
                with open(master_file, 'w') as jdata:
                    json.dump(jfile, jdata)
                with open(filename, 'w') as jdata:
                    json.dump(jfile, jdata)
                # then delete file
                os.remove(filename)
                os.remove(master_file)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect
        elif os.path.isfile(master_file) and not os.path.isfile(filename): # only master password exists
            if stored_master == entered_master:
                spinner = Halo(text=colored("Deleting all data...", "red"), spinner=self.dots_, color="red")
                spinner.start()
                # and clear the data
                jfile = {}
                with open(master_file, 'w') as jdata:
                    json.dump(jfile, jdata)
                os.remove(master_file)
                spinner.stop()
            else:
                raise MasterPasswordIncorrect