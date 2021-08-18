import Crypto
import binascii
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#tomar los tiempos de ejcución
from timeit import default_timer

random_generator = Crypto.Random.new().read # fuente segura de Entropía
#Generación de llaves
#       PRIVADA
# Argumentos (Tamaño de llaves,numero aleatorio)
private_key = RSA.generate(1024, random_generator)

#       PUBLICA
# Se genera a partir de la llave privada
public_key = private_key.publickey()
#############################
#           CIFRADO         #
#############################
message = "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
message	= bytes.fromhex(message)
t0 = default_timer()
cipher = PKCS1_OAEP.new(public_key) #Objeto para cifrar
encrypted_message = cipher.encrypt(message) # MENSAJE CIFRADO
t1 = default_timer()
print("{0:0.10f}".format(t1-t0))
#print(encrypted_message)

################################
#           DESCIFRADO         #
################################
#   Para descifrar se hace uso de la llave privada
#encrypted_message = base64.b64decode(image)
t0 = default_timer()
cipher = PKCS1_OAEP.new(private_key) #Objeto de descifrado
message = cipher.decrypt(encrypted_message) #Mensaje en Claro
t1 = default_timer()
print("{0:0.10f}".format(t1-t0))
#print(message)