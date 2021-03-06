import Crypto
import binascii
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#tomar los tiempos de ejcución
from timeit import default_timer

random_generator = Crypto.Random.new().read # fuente segura de Entropía
#Generación de llaves
#Modulo
n=int("9195E9854FA04A1433D4E22048951426A0ACFC6FE446730579D742CAEA5FDF6590FAEC7F71F3EBF0C6408564987D07E19EC07BC0F601B5E6ADB28D9AA6148FCC51CFF393178983790CC616C0EF34AB50DC8444F44E24117B46A47FA3630BF7E696865BFC245F7C3A314CD48C583D7B2223AF06881158557E37B3CC370AE6C8D5",16)
#Exponente público
e=int("010001",16)
#Exponente privado
d=int("05B2DDE134ACB6E448E31C618720796EC9A5FBD0FAC3DC876A5832BFC94CD76C725B0AC6DCFF09F7F2CAB3C356F4B89F96F1E73B8BBAFABE7CD8C5BCE2A360BD8A3CE2767A2F83A6B143C2446D5A0388748F91813BB5E7A6CEA402368842DBC50C11EFE6B26CB08B53B83BC7FB17D5A62C39A6CCC718165D59375BE387642601",16)
#Primer factor primo
np1=int("B5D49FA4F78255C12DD125EF76EB039DA81CECF80C314E1E067706E200101117EF3D03479EEC26DBFA7355CD2913F3AD7F465D6F1424D8A8506A1E8852606A39",16)
#Segundo Factor priemo
np2=int("CCF876B8B473F7E05C9551EE3F7ECA0C57CB542E0849B663026CB8A2896E75B80CC6D2415425DD5987ECB47AE7DCD091BA3F609B0FE02E969C4E7DC29E36437D",16)
#Coeficiente
coef=int("036F02D351D7831238E5361BAC0D60888D0F2AB38B0DED7A14A90E2CF1D4D3BD72395F9667ED279889987808288FFF2739927A2868F01A3036BD85D44DDA9FD5",16)

#       PRIVADA
# Argumentos (Tamaño de llaves,numero aleatorio)
private_key = RSA.construct((n,e,d,np1,np2,coef),consistency_check=True)

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