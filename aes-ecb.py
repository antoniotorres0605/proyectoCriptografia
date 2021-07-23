import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from time import time

key = '0000000000000000000000000000000000000000000000000000000000000000'
key = bytes.fromhex(key)
text = '014730f80ac625fe84f026c60bfd547d'
text = bytes.fromhex(text)

aes = AES.new(key, AES.MODE_ECB)
# Aes Cifrado
tiempo_inicial = time()
encrypt_aes = aes.encrypt(pad(text,AES.block_size))
# Impresi[on de Mensaje cifrado 
tiempo_final = time()
print(encrypt_aes.hex())
print("Tiempo de ejecución de cifrado: ",(tiempo_final-tiempo_inicial),"segundos")

tiempo_inicial = time()
msg = unpad(aes.decrypt(encrypt_aes),AES.block_size)
tiempo_final = time()
print(msg.hex())
print("Tiempo de ejecución de descifrado: ",(tiempo_final-tiempo_inicial),"segundos")
