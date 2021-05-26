#!/bin/python3
import dsfjsdfskl
import os
import secrets
from Crypto.Cipher import AES
from getpass import getpass
from pbkdf2 import PBKDF2
import toml
from base64 import b64encode, b64decode
import models
import argparse

parser = argparse.ArgumentParser(description="CLI password manager")
parser.add_argument(
    "--db", default="main", type=str, help="Database name (default: main)"
)
parser.add_argument(
    "action",
    type=str,
    help="Action (show_categories, show_entry, "
    "rm_category, rm_entry, create_entry, create_category)",
)
parser.add_argument("--category", "-c", default="__global__", type=str, help="Category")
parser.add_argument("--name", "-n", default=None, type=str, help="Entry name")
parser.add_argument("--type", "-t", default="0", type=str, help="Record type name")
parser.add_argument("--value", "-v", default=None, type=str, help="Record value name")
args = parser.parse_args()

base_path = os.path.join(os.getenv("HOME", os.getenv("APPDATA", "")), ".smpp")
if not base_path:
    print(
        'Add to your PATH environment variable "HOME", containing absolute path to home folder.'
    )
    exit(100)
if not os.path.isdir(base_path):
    os.mkdir(base_path)
os.chdir(base_path)

base_path = os.path.join(base_path, args.db)

if not os.path.isdir(base_path):
    os.mkdir(base_path)
os.chdir(base_path)

if not os.path.isfile("config.toml"):
    config = {}
    f = open("config.toml", "w")
    f.close()
else:
    config = {}
    with open("config.toml", "r") as f:
        try:
            config = toml.load(f)
        except toml.TomlDecodeError:
            print(
                "Database config invalid! Database damaged. "
                "Fix or delete file " + os.path.join(base_path, "config.toml")
            )
            exit(1)


def save_config():
    global config, base_path
    with open("config.toml", "w") as f:
        toml.dump(config, f)


config["salt"] = config.get("salt", b64encode(secrets.token_bytes(32)).decode())
salt = b64decode(config["salt"])

password = PBKDF2(getpass("Password: "), salt).read(32)
config["password"] = config.get(
    "password", b64encode(PBKDF2(password, salt).read(32)).decode()
)
password_hash = b64decode(config["password"])
if PBKDF2(password, salt).read(32) != password_hash:
    print("Password invalid!")
    exit(2)
del password_hash, salt

if not config.get("master_password"):
    cipher = AES.new(password, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(secrets.token_bytes(32))
    config["master_password"] = b64encode(ciphertext).decode()
    config["master_password_nonce"] = b64encode(cipher.nonce).decode()
    config["master_password_tag"] = b64encode(tag).decode()
nonce, tag, ciphertext = (
    config["master_password_nonce"],
    config["master_password_tag"],
    config["master_password"],
)
nonce, tag, ciphertext = b64decode(nonce), b64decode(tag), b64decode(ciphertext)
cipher = AES.new(password, AES.MODE_EAX, nonce)
password = cipher.decrypt_and_verify(ciphertext, tag)
del nonce, tag, ciphertext

save_config()

db = models.Database(base_path, password)


if args.action == "show_categories":
    for c in db.categories:
        print("category:", c.name)
elif args.action == "show_entries":
    for c in db.categories:
        if c.name == args.category:
            print("category:", args.category)
            for e in c.entries:
                print("\tname:", e.name)
                for r in e.records:
                    print("\t\ttype:", r.type)
                    print("\t\tvalue:", r.value)
                    print()
elif args.action == "create_entry":
    db.create_entry(
        args.category, args.name, [{"type": args.type, "value": args.value}]
    )
elif args.action == "create_category":
    db.create_category(args.name)
elif args.action == "rm_entry":
    for c in db.categories:
        if c.name == args.category:
            for e in c.entries:
                if e.name == args.name:
                    db.delete_entry(c, e)
                    break
            break
elif args.action == "rm_category":
    for c in db.categories:
        if c.name == args.category:
            db.delete_category(c)
            break
