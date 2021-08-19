# It is a mode of operation where each plaintext block gets XOR-ed with 
# the previous ciphertext block prior to encryption.
# -------------------------------------------------
# AES 
# 1024 bits
# Modo CBC
# -------------------------------------------------

# --- BIBLIOTECAS NECESARIAS --
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from timeit import default_timer

# Generación de DATOS, Vector de Inicialización y llave con base al NIST

data = "014730f80ac625fe84f026c60bfd547d"
data = bytes.fromhex(data)

IV = "00000000000000000000000000000000"
IV = bytes.fromhex(IV)

key = "0000000000000000000000000000000000000000000000000000000000000000"
key = bytes.fromhex(key)

# Objeto de cifrado y descifrado
cipher = AES.new(key, AES.MODE_CBC, iv=IV)

#######################################################
####################### CIFRADO #######################
#######################################################

# Se toma el instante 1 del tiempo
t0 = default_timer()

# Proceso de cifrado
ct_bytes = cipher.encrypt(pad(data, AES.block_size))

# Se toma el instante 2 del tiempo
t1 = default_timer()

# Codificación del vector de inicialización
iv = b64encode(cipher.iv).decode('utf-8')

# Codificación de mensaje cifrado
ct = b64encode(ct_bytes).decode('utf-8')

# Resultado
print("{0:0.10f}".format(t1-t0))
#print(ct)

########################################################
###################### DESCIFRADO ######################
########################################################

# Se toma el instante 1 del tiempo
t0 = default_timer()

# Objeto para el decodificado 
cipher = AES.new(key, AES.MODE_CBC, iv=IV)

# Se toma el instante 2 del tiempo
t1 = default_timer()

# Proceso de descifrado
pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)


print("{0:0.10f}".format(t1-t0))

#print(pt.hex())