import enc, os

salt = os.urandom(8)
password = '12345'
plain = 'abcdefg'

cryptor = enc.cryptor()
encrypted = cryptor.encrypt(plain, salt, password)
print(encrypted)

decrypted = cryptor.decrypt(encrypted, password)
print(decrypted)


encrypted = "U2FsdGVkX1/6saueyNdhVJI0+S7KAtdUFJcC85Kfmgw="
password="a12345678_"
decrypted = cryptor.decrypt(encrypted, password)
print(decrypted)
