from base64 import b64decode, b64encode
import os
from Crypto.Cipher import AES
import secrets
import pickle
import defaults
from functions import *
from shutil import rmtree


class Database:
    def __init__(self, path, password):
        self.path = path
        self.password = password
        self.config = {}
        self.categories = []
        self.setup()

    @staticmethod
    def open_file(file, password):
        file = open(file, 'rb')
        nonce = file.read(16)
        tag = file.read(16)
        cipher = AES.new(password, AES.MODE_EAX, nonce)
        ret = pickle.loads(cipher.decrypt_and_verify(file.read(), tag))
        file.close()
        return ret

    @staticmethod
    def save_file(data, path, password):
        data = pickle.dumps(data)
        cipher = AES.new(password, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with open(path, 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)

    def save_config(self):
        self.save_file(self.config, 'config', self.password)

    def create_category(self, name):
        if name not in [str(i) for i in self.categories]:
            pos = secrets.randbits(24)
            c = defaults.category
            c['id'] = pos
            c['name'] = name
            os.mkdir(str(pos))
            data = {'name': name}
            self.save_file(data, os.path.join(str(pos), 'data'), self.password)
            self.load()

    def create_entry(self, category, name, records):
        for c in self.categories:
            if c.name == category:
                for e in c.entries:
                    if e.name == name:
                        print('Entry with same name already exists!')
                        exit(5)
                data = defaults.entry
                pos = secrets.randbits(24)
                data['id'] = pos
                data['name'] = name
                data['records'] = [i | defaults.entry for i in records]
                p = os.path.join(str(c.pos), str(pos))
                os.mkdir(p)
                self.save_file(data, os.path.join(p, 'data'), self.password)
                return
        print('Category not found')
        exit(3)

    @staticmethod
    def delete_entry(category, entry):
        if not os.path.isdir(category.pos):
            print('Category not found')
            exit(3)
        if not os.path.isdir(os.path.join(category.pos, entry.pos)):
            print('Entry not found')
            exit(4)
        rmtree(os.path.join(category.pos, entry.pos))

    @staticmethod
    def delete_category(category):
        if not os.path.isdir(category.pos):
            print('Category not found')
            exit(3)
        rmtree(category.pos)

    def load_entries(self, category):
        for e in os.listdir(category.pos):
            path = os.path.join(category.pos, e)
            if os.path.isdir(path):
                data = self.open_file(os.path.join(path, 'data'), self.password)
                r = []
                for re in data['records']:
                    r.append(Record(re['type'], re['value']))
                e = Entry(data['name'], r, e)

    def load(self):
        self.categories = []
        for c in os.listdir():
            pos = str(c)
            if os.path.isdir(c):
                c = self.open_file(os.path.join(c, 'data'), self.password)
                c = defaults.category | c
                ca = Category(c['name'], pos)
                self.categories.append(ca)
                self.load_entries(ca)

    def setup(self):
        os.chdir(self.path)
        if not os.path.isdir('data'):
            os.mkdir('data')
        self.path = os.path.join(self.path, 'data')
        os.chdir(self.path)
        if not os.path.isfile('config'):
            self.save_file(defaults.db_config, 'config', self.password)
        self.config = self.open_file('config', self.password)
        self.config = defaults.db_config | self.config
        self.load()
        self.create_category('__global__')


class Category:
    def __init__(self, name, pos):
        self.name = name
        self.pos = pos
        self.entries = []

    def add_entries(self, entry):
        self.entries.append(entry)

    def __str__(self):
        return self.name


class Entry:
    def __init__(self, name, records, pos):
        self.name = name
        self.records = records
        self.pos = pos


class Record:
    def __init__(self, typ, value):
        self.type = typ
        self.value = value
