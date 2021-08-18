import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from time import time
from timeit import default_timer

key = '0000000000000000000000000000000000000000000000000000000000000000'
key = bytes.fromhex(key)
text = '014730f80ac625fe84f026c60bfd547d'
text = bytes.fromhex(text)

aes = AES.new(key, AES.MODE_ECB)
# Aes Cifrado
t0 = default_timer()
encrypt_aes = aes.encrypt(pad(text,AES.block_size))
# Impresion de Mensaje cifrado 
t1 = default_timer()
#print(encrypt_aes.hex())
print("{0:0.10f}".format(t1-t0))
#print("Tiempo de ejecución de cifrado: ",(tiempo_final-tiempo_inicial),"segundos")

t0 = default_timer()
msg = unpad(aes.decrypt(encrypt_aes),AES.block_size)
t1 = default_timer()
#print(msg.hex())
print("{0:0.10f}".format(t1-t0))
#print("Tiempo de ejecución de descifrado: ",(tiempo_final-tiempo_inicial),"segundos")
