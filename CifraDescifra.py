# --- BIBLIOTECAS NECESARIAS --
# Padding y formateo de datos necesarios para el cifrado
import base64
import Crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from timeit import default_timer
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Random import get_random_bytes
import binascii
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#Lectura de archivo
import fileinput
#Impresión grafico
import numpy as np
import matplotlib.pyplot as plt 

def toBytes(m):
    cb = bytes.fromhex(m)
    return cb

def aes_ecb(text):
    # -------------------------------------------------
    # AES 
    # 1024 bits
    # Modo ECB
    # -------------------------------------------------
    # Llave de 256 bits
    key = "0000000000000000000000000000000000000000000000000000000000000000"
    key = bytes.fromhex(key)

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
    tc_aes_ecb.append("{0:0.10f}".format(t1-t0))

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
    td_aes_ecb.append("{0:0.10f}".format(t1-t0))

def aes_cbc(data):
    # -------------------------------------------------
    # AES 
    # 1024 bits
    # Modo ECB
    # -------------------------------------------------
    # Generación de DATOS, Vector de Inicialización y llave con base al NIST
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
    tc_aes_cbc.append("{0:0.10f}".format(t1-t0))

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
    td_aes_cbc.append("{0:0.10f}".format(t1-t0))

def rsa_oaep(message):
    # -------------------------------------------------
    # RSA
    # 1024 bits
    # Modo OAEP
    # -------------------------------------------------
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
    t0 = default_timer()
    cipher = PKCS1_OAEP.new(public_key) #Objeto para cifrar
    encrypted_message = cipher.encrypt(message) # MENSAJE CIFRADO
    t1 = default_timer()
    tc_rsa_oaep.append("{0:0.10f}".format(t1-t0))

    ################################
    #           DESCIFRADO         #
    ################################
    #   Para descifrar se hace uso de la llave privada
    t0 = default_timer()
    cipher = PKCS1_OAEP.new(private_key) #Objeto de descifrado
    message = cipher.decrypt(encrypted_message) #Mensaje en Claro
    t1 = default_timer()
    td_rsa_oaep.append("{0:0.10f}".format(t1-t0))

def promedios(vector,tam):
    suma = 0
    for i in range(tam):
        suma = suma + float(vector[i])
    return suma/float(tam)

def grafico(c1,c2,c3,d1,d2,d3,c):
    """
    El orden de los vectores es:
    AES ECB, AES CBC, RSA OAEP
    """
    x=np.arange(100)
    #Convertir a numeros
    for i in range(c):
        c1[i] = float(c1[i])
        c2[i] = float(c2[i])
        c3[i] = float(c3[i])
        d1[i] = float(d1[i])
        d2[i] = float(d2[i])
        d3[i] = float(d3[i])
    fig, (ax1, ax2) = plt.subplots(1, 2)
    ax1.plot(x,c1, label='AES ECB')
    ax1.plot(x,c2, label='AES CBC')
    ax1.plot(x,c3, label='RSA OAEP')
    plt.legend()
    ax2.plot(x,d1, label='AES ECB')
    ax2.plot(x,d2, label='AES CBC')
    ax2.plot(x,d3, label='RSA OAEP')
    plt.legend()
    ax1.set_title("Grafíco de Cifrados")
    ax2.set_title("Grafíco de Descifrados")
    plt.show()

#Vectores para tiempos
#Cifrado
tc_aes_ecb = []
tc_aes_cbc = []
tc_rsa_oaep = []
#Descifrado
td_aes_ecb = []
td_aes_cbc = []
td_rsa_oaep = []

#contador de vectores
c = 0

#Lectura de archivo
for line in fileinput.input():
    msg = toBytes(line.strip('\n'))
    c = c + 1
    aes_ecb(msg)
    aes_cbc(msg)
    rsa_oaep(msg)

#Promedios
pc_aes_ecb = promedios(tc_aes_ecb,c)
pc_aes_cbc = promedios(tc_aes_cbc,c)
pc_rsa_oaep = promedios(tc_rsa_oaep,c)
pd_aes_ecb = promedios(td_aes_ecb,c)
pd_aes_cbc = promedios(td_aes_cbc,c)
pd_rsa_oaep = promedios(td_rsa_oaep,c)

print("-----------------------------  CIFRADOS  ------------------------------")
print("Vector\tAES ECB\t\tAES CBC\t\tRSA OAEP")
for i in range(c):
    print(str(i+1) + "\t" + str(tc_aes_ecb[i]) + "\t" + str(tc_aes_cbc[i]) + "\t" + str(tc_rsa_oaep[i]))
print("---------------------------------------------------------------------")
print("Prom:\t" + "{:.10f}".format(pc_aes_ecb) + "\t{:.10f}".format(pc_aes_cbc) + "\t{:.10f}".format(pc_rsa_oaep))
print("#####################################################################\n\n")

print("--------------------------  DESCIFRADOS  ---------------------------")
print("Vector\tAES ECB\t\tAES CBC\t\tRSA OAEP")
for i in range(c):
    print(str(i+1) + "\t" + str(td_aes_ecb[i]) + "\t" + str(td_aes_cbc[i]) + "\t" + str(td_rsa_oaep[i]))
print("---------------------------------------------------------------------")
print("Prom:\t" + "{:.10f}".format(pd_aes_ecb) + "\t{:.10f}".format(pd_aes_cbc) + "\t{:.10f}".format(pd_rsa_oaep))
print("#####################################################################\n\n")

grafico(tc_aes_ecb,tc_aes_cbc,tc_rsa_oaep,td_aes_ecb,td_aes_cbc,td_rsa_oaep,c)