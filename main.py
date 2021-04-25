import os
import secrets
import pickle
from Crypto.Cipher import AES
from getpass import getpass
from pbkdf2 import PBKDF2
import toml
from base64 import b64encode, b64decode
import models
from sys import argv


try:
    db_name = argv[1]
except IndexError:
    db_name = 'main'

base_path = os.path.join(os.getenv('HOME', ''), '.smpp')
base_path = os.path.join(base_path, db_name)

if not os.path.isdir(base_path):
    os.mkdir(base_path)
os.chdir(base_path)

if not os.path.isfile('config.toml'):
    config = {}
    f = open('config.toml', 'w')
    f.close()
else:
    config = {}
    with open('config.toml', 'r') as f:
        try:
            config = toml.load(f)
        except toml.TomlDecodeError:
            print('Database config invalid! Database damaged. '
                  'Fix or delete file '+os.path.join(base_path, 'config.toml'))
            exit(1)


def save_config():
    global config, base_path
    with open('config.toml', 'w') as f:
        toml.dump(config, f)


config['salt'] = config.get('salt', b64encode(secrets.token_bytes(32)).decode())
salt = b64decode(config['salt'])

password = PBKDF2(getpass('Password: '), salt).read(32)
config['password'] = config.get('password', b64encode(PBKDF2(password, salt).read(32)).decode())
password_hash = b64decode(config['password'])
if PBKDF2(password, salt).read(32) != password_hash:
    print('Password invalid!')
    exit(2)
del password_hash, salt

if not config.get('master_password'):
    cipher = AES.new(password, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(secrets.token_bytes(32))
    config['master_password'] = b64encode(ciphertext).decode()
    config['master_password_nonce'] = b64encode(cipher.nonce).decode()
    config['master_password_tag'] = b64encode(tag).decode()
nonce, tag, ciphertext = config['master_password_nonce'], config['master_password_tag'], \
                         config['master_password']
nonce, tag, ciphertext = b64decode(nonce), b64decode(tag), b64decode(ciphertext)
cipher = AES.new(password, AES.MODE_EAX, nonce)
password = cipher.decrypt_and_verify(ciphertext, tag)
del nonce, tag, ciphertext

save_config()

db = models.Database(base_path, password)
