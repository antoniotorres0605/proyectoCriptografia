from Crypto.Cipher import AES
 
key = 'urirociojoseomarurirociojoseomar'
 
cipher = AES.new(key, AES.MODE_ECB)
msg =cipher.encrypt('Criptografia 2021-2')
print (type(msg))
 
print(msg.encode("hex"))
 
decipher = AES.new(key, AES.MODE_ECB)
print(decipher.decrypt(msg))
