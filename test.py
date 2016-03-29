import enc, os

salt = os.urandom(8)
password = '12345'
plain = 'abcdefg'

cryptor = enc.cryptor()
encrypted = cryptor.encrypt(plain, salt, password)
print(encrypted)

decrypted = cryptor.decrypt(encrypted, password)
print(decrypted)

