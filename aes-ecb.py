# -------------------------------------------------
# AES 
# 1024 bits
# Modo ECB
# -------------------------------------------------

# --- BIBLIOTECAS NECESARIAS --
# Padding y formateo de datos necesarios para el cifrado
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from time import time
from timeit import default_timer

# Llave de 256 bits
key = "0000000000000000000000000000000000000000000000000000000000000000"
key = bytes.fromhex(key)

# Mensaje en claro
text = "014730f80ac625fe84f026c60bfd547d"
text = bytes.fromhex(text)

# Objeto de cifrado y descifrado
aes = AES.new(key, AES.MODE_ECB)

#######################################################
####################### CIFRADO #######################
#######################################################

# Se toma el instante 1 del tiempo
t0 = default_timer()

# Proceso de cifrado
encrypt_aes = aes.encrypt(pad(text,AES.block_size))

# Se toma el instante 2 del tiempo
t1 = default_timer()
#print(encrypt_aes.hex())
print("{0:0.10f}".format(t1-t0))


########################################################
###################### DESCIFRADO ######################
########################################################

# Se toma el instante 1 del tiempo
t0 = default_timer()

# Proceso de descifrado
msg = unpad(aes.decrypt(encrypt_aes),AES.block_size)

# Se toma el instante 1 del tiempo
t1 = default_timer()
#print(msg.hex())
print("{0:0.10f}".format(t1-t0))
#print("Tiempo de ejecución de descifrado: ",(tiempo_final-tiempo_inicial),"segundos")
