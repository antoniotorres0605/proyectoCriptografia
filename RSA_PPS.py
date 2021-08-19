#Algoritmo de firma digital
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
#tomar los tiempos de ejcución
from timeit import default_timer

random_generator = Crypto.Random.new().read # fuente segura de Entropía
#Generación de llaves
#       PRIVADA
# Argumentos (Tamaño de llaves,numero aleatorio)
private_key = RSA.generate(1024, random_generator)

#Mensaje
m = "0000000000000000000000000000000000000000"
m = bytes.fromhex(m)

t0 = default_timer()
#Generacion del hash
h = SHA256.new(m)
#Mensaje firmado
s = pss.new(private_key).sign(h)
t1 = default_timer()
print("{0:0.10f}".format(t1-t0))

#Verificacion del mensaje
t0 = default_timer()
#Generacion del hash
hr = SHA256.new(m)
#Objeto verificador
verifier = pss.new(private_key)
try:
    verifier.verify(hr, s)
    print("La firma es autentica")
except(ValueError, TypeError):
    print("La firma no es autentica")
t1 = default_timer()
print("{0:0.10f}".format(t1-t0))
