# -------------------------------------------------
# ECDSA Prime Field
# 512 bits - SHA 512 
# q = 512 bits
# -------------------------------------------------

# --- BIBLIOTECAS NECESARIAS --

# -- ECDSA Prime Field 512 bits - SHA 512 
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography import exceptions

# -- Medir tiempo
import time 

# ---- ALGORITMO -----

def ecdsa521(msg):
	# --- PARAMETROS --

	# -- Curva

	E = ec.SECP521R1() # Se crea una instancia de la curva eliptica sobre un campo primo 

	# -- Par de llaves

	# Llave privada
	x = "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538"
	# Se obtiene el numero entero correspondiente a la representacion en hexadecimal
	x = int(x,16)

	# Llave publica U = xG

	# Coordenada x
	Ux = "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4"
	# Se obtiene el numero entero correspondiente a la representacion en hexadecimal
	Ux = int(Ux,16)
	# Coordenada y
	Uy = "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	# Se obtiene el numero entero correspondiente a la representacion en hexadecimal
	Uy = int(Uy,16)

	# --- GENERACION DE LLAVES --

	# Llave publica
	pubECC = ec.EllipticCurvePublicNumbers(x=Ux, y=Uy, curve=E)
	pubKECC = pubECC.public_key()

	# Llave privada
	privECC = ec.EllipticCurvePrivateNumbers(private_value=x, public_numbers=pubECC)
	privKECC = privECC.private_key()

	# -- FIRMA --
	inicio = time.time()
	ECC_sign = privKECC.sign(data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
	fin = time.time()
	r,s = utils.decode_dss_signature(ECC_sign)
	t_firma = fin - inicio
	#print("tiempo = %f" % (t_firma))
	#print("r = {}".format(hex(s)))
	#print("s = {}".format(hex(r)))

	# -- VERIFICACION --
	try:
		inicio = time.time()
		pubKECC.verify(signature=ECC_sign, data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
		fin = time.time()
		t_verificacion = fin - inicio
		#print("tiempo = %f" % (t_verificacion))
		return t_firma,t_verificacion 
	except(exceptions.InvalidSignature):
		#print("tiempo =-1")
		return t_firma,-1
