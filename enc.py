import hashlib, binascii, base64
from passlib.utils.pbkdf2 import pbkdf1
from Crypto.Cipher import AES

class cryptor:

    _pad = lambda s, padsize: s + (padsize - len(s) % padsize) * chr(padsize - len(s) % padsize)
    _unpad = lambda s : s[:-ord(s[len(s)-1:])]
    _magic = 'Salted__'

    @classmethod
    def _hasher(cls, algo, data):
        hashes = {'md5': hashlib.md5, 'sha256': hashlib.sha256, 'sha512': hashlib.sha512}
        h = hashes[algo]()
        h.update(data)
        return h.digest()

    # pwd and salt must be bytes objects
    @classmethod
    def _openssl_kdf(cls, algo, pwd, salt, key_size, iv_size):


        print('PWD=' + binascii.hexlify(pwd).decode('ascii').upper())

        if algo == 'md5':
            temp = pbkdf1(pwd, salt, 1, 16, 'md5')
        else:
            temp = b''

        print('FD=' + binascii.hexlify(temp).decode('ascii').upper())

        fd = temp
        while len(fd) < key_size + iv_size:
            temp = cls._hasher(algo, temp + pwd + salt)
            fd += temp

        key = fd[0:key_size]
        iv = fd[key_size:key_size+iv_size]

        print('salt=' + binascii.hexlify(salt).decode('ascii').upper())
        print('key=' + binascii.hexlify(key).decode('ascii').upper())
        print('iv=' + binascii.hexlify(iv).decode('ascii').upper())

        return key, iv

    @classmethod
    def encrypt(cls, data, salt, password):
        key, iv = cls._openssl_kdf('md5', bytes(password, encoding='ascii'), salt, 32, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = cls._magic.encode('ascii') + salt + cipher.encrypt(cls._pad(data, 16).encode('ascii'))
        msg = base64.b64encode(msg)
        return msg.decode('ascii')

    @classmethod
    def decrypt(cls, data:str, password):
        m = base64.b64decode(data)
        if m[0:len(cls._magic)].decode('ascii') != cls._magic:
            raise ValueError()
        data = base64.b64decode(data)[len(cls._magic):]
        salt = data[0:8]
        data = data[8:]
        key, iv = cls._openssl_kdf('md5', bytes(password, encoding='ascii'), salt, 32, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        msg = cipher.decrypt(data)
        aaaa = msg.decode('ascii')
        print(ord(aaaa[16]))
        return cls._unpad(msg.decode('ascii')) + "]]]"