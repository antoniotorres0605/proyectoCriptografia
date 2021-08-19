"""
PROYECTO FINAL CRITOGRAFÍA
20 de agosto de 2021
Creación y Verificación de Firmas
Ibarra Badillo Omar
Landín Martínez Uri Raquel
Torres Galván José Antonio
Valdes Vargas Rocio Monserrat 
"""

# --- BIBLIOTECAS NECESARIAS --
#RSA PPS
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
# ECDSA Binary Field 571 bits - Koblitz Curve - SHA 512 
# ECDSA Prime Field 512 bits - SHA 512 
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions
# -- DSA - 1024 bits
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
#Medir tiempo
from timeit import default_timer
#Lectura de archivo
import fileinput
#Impresión grafico
import numpy as np
import matplotlib.pyplot as plt 

def toBytes(m):
    cb = bytes.fromhex(m)
    return cb

def rsapps(m):
    # -------------------------------------------------
    # RSA PPS
    # 1024 bits
    # -------------------------------------------------
    #Generación de llaves
    #Componentes de la llave
    #Modulo
    n = int("C4877F32540FCB427C7E875009D31000E6DC9C6B8BE6D56AE004E8909FBF379CA25D440516477E606F1C7B6C9F0BD1A10032C05811B4F7D4DEA576D3BC4EB5BB64808D561863E6CEA285B6F5D1FC465A37C18AC0F80FDBB1E686088BA661E17527EAE81147123F2314E2B9AD5AA546526C8126138139AAABFF716D900A7E32E7", 16)
    #Exponente publico
    e = int("010001", 16)
    #Exponente privado
    d = int("0586116B26B5B2EED174F4F4A8F207B71EC600977D3D25AE75516DFFF29D7B40A9C7994BD34E7B1CD6C2A42D6F62F3A764CC085FF14F76CFC2DA3FB6BFCA2E8D63161AE6A165E3A5EC5C5F354B71244C2BE5CD96234235AE4F0A5E3904D75D569743418B5CEB5D9CF9746E56BC543CCF115B3451D6414C16A470D62081EFE731",16)
    #Primer factor primo
    np = int("FE835D94A2A7B98226BAA644EA61596469C446FFE1CBE627EF38862141C5FE263ADBFC9D595EC4F0032CE8FB36FF6829EF8431D7DD488C26DB497C29627F7FA3",16)
    #Segundo factor primo
    nq = int("C5AD6A065A251996F9AAE1C328DD64DB17EE0C72DCF52A8E97501D0BBD397730445BCD58E6EDC6501B3E5257276772681E2A959510302B0960447E6AD11363ED",16)
    #Coeficiente
    q = int("B85E28968D974B9574EB0A0FB5087E866910B3B6A1BF219EB64001986FB6A6F5FA15BD3042FADD24B4E005D858799E45427D3A5CA4D4C269FDF11D57CA2D7BCD",16)
    #       PRIVADA
    private_key = RSA.construct((n, e, d, nq, np, q), consistency_check=True)

    t0 = default_timer()
    #Generacion del hash
    h = SHA256.new(m)
    #Mensaje firmado
    s = pss.new(private_key).sign(h)
    t1 = default_timer()
    t_rsapps_f.append("{0:0.10f}".format(t1-t0))

    #Verificacion del mensaje
    t0 = default_timer()
    #Generacion del hash
    hr = SHA256.new(m)
    #Objeto verificador
    verifier = pss.new(private_key)
    try:
        verifier.verify(hr, s)
        #print("La firma es autentica")
        t1 = default_timer()
        t_rsapps_v.append("{0:0.10f}".format(t1-t0))
    except(ValueError, TypeError):
        print("La firma no es autentica")
        pass
    
def dsa1024(msg):
    # -------------------------------------------------
    # DSA 
    # 1024 bits
    # -------------------------------------------------
    # --- PARAMETROS --
    # Valores tomados del archivo proporcionado por CAVS 11.2
    p=int("f5422387a66acb198173f466e987ca692fd2337af0ed1ec7aa5f2e2088d0742c2d41ded76317001ca4044115f00aff09ad59d49b07c35ec2b25088be17ac391af17575d52c232153df94f0023a0a17ca29d8548dfa08c5f034bad0bd4511ffae6b3c504c6f728d31d1e92aad9e88382a8a42b050441a747bb71dd84cb01d9ee7",16)
    q=int("f4a9d1750b46e27c3af7587c5d019ffc99f11f25",16)
    g=int("7400ad91528a6c9e891f3f5fce7496ef4d01bf91a979736547049406ab4a2d2fe49fa3730cfb86a5af3ff21f5022f07e4ee0c15a88b8bd7b5f0bf8dea3863afb4f1cac16aba490d93f44be79c1cd01ce2e12dfdb75c593d64e5bf97e839526dbcc0288cd3beb2fd7941f67d138faa88f9de90901efdc752569a4d1afbd193846",16)
    x=int("485e8ad4a4e49a85e0397af0bb115df175ead894",16)
    y=int("ec86482ea1c463198d074bad01790283fb8866e53ab5e821219f0f4a25e7d0473f9cbd2ab7348625d322ea7f09ec9a15bbcc5a9ff1f3692392768970e9e865545d3aa2934148f6d0a6ec410a16d5059c58ce428912f532cbc8f9bbbcf3657367d159212c11afd856587b1b092ab1bdae3c443661e6ba27078d03eb31e63e5922",16)

    # --- GENERACION DE LLAVE --
    key = DSA.construct((y,g,p,q,x),consistency_check=True)

    # -- Adecuacion mensaje
    msg = "96452f7f94b9cc004931df8f8118be7e56f16a1502e00934f16c96391b83d72490be8ffa54e7f6676eb966a63ce657a6095f8d65e1cf90a0a4685daf5ae35babc6c290d13ed9152bba0cc76d2a5a401d0d1b06f63f85018f12753338a16da32461d89acef996129554b46ca9f47b612b89ad3b90c20b4547631a809b982797da"
    inicio =  default_timer()
    m = msg.encode("utf-8")
    hash_msg = SHA256.new(m)

    # -- FIRMA --
    sign = DSS.new(key, 'fips-186-3')
    s = sign.sign(hash_msg)
    fin =  default_timer()
    t_dsa1024_f.append("{0:0.10f}".format(fin-inicio))
    
    # -- VERIFICACION --

    # -- Adecuación del mensaje
    inicio =  default_timer()
    m = msg.encode("utf-8")
    hash_msg = SHA256.new(m)
    # Se obtiene llave publica
    pKey = DSA.import_key(key.publickey().export_key())
    # Obtener firma para verificacion 
    verify = DSS.new(pKey, 'fips-186-3')
    #print(verify)

    # -- Verifica la autenticidad del mensaje
    try:
        verify.verify(hash_msg, s)
        fin =  default_timer()
        t_dsa1024_v.append("{0:0.10f}".format(fin-inicio))
        #print ("La firma coincide")
    except ValueError:
        #print ("La firma no coincide")
        pass

def ecdsa571(msg):
    # -------------------------------------------------
    # ECDSA Binary Field 
    # 571 bits - Koblitz Curve - SHA 512 
    # q = 570 bits
    # -------------------------------------------------
    # --- PARAMETROS --

    # -- Curva
    E = ec.SECT571K1()  # Se crea una instancia de la curva especificada en el NIST K-571

    # -- Par de llaves

    # Llave privada

    x = "0C16F58550D824ED7B95569D4445375D3A490BC7E0194C41A39DEB732C29396CDF1D66DE02DD1460A816606F3BEC0F32202C7BD18A32D87506466AA92032F1314ED7B19762B0D22"
    # Se obtiene el numero entero correspondiente a la representacion en hexadecimal
    x = int(x, 16)

    # Llave publica U = xG

    # Coordenada x
    Ux = "6CFB0DF7541CDD4C41EF319EA88E849EFC8605D97779148082EC991C463ED32319596F9FDF4779C17CAF20EFD9BEB57E9F4ED55BFC52A2FA15CA23BC62B7BF019DB59793DD77318"
    # Se obtiene el numero entero correspondiente a la representacion en hexadecimal
    Ux = int(Ux, 16)
    # Coordenada y
    Uy = "1CFC91102F7759A561BD8D5B51AAAEEC7F40E659D67870361990D6DE29F6B4F7E18AE13BDE5EA5C1F77B23D676F44050C9DBFCCDD7B3756328DDA059779AAE8446FC5158A75C227"
    # Se obtiene el numero entero correspondiente a la representacion en hexadecimal
    Uy = int(Uy, 16)

    # --- GENERACION DE LLAVES --

    # Llave publica
    pubE = ec.EllipticCurvePublicNumbers(x=Ux, y=Uy, curve=E)
    pubKE = pubE.public_key()
    #print(pubKE)

    # Llave privada
    privE = ec.EllipticCurvePrivateNumbers(private_value=x, public_numbers=pubE)
    privKE = privE.private_key()
    #print(privKE)

    # -- FIRMA --

    inicio =  default_timer()
    ECC_s = privKE.sign(data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
    fin =  default_timer()
    t_ecdsa571_f.append("{0:0.10f}".format(fin-inicio))
    r,s = utils.decode_dss_signature(ECC_s)
    #print("r = ", hex(r))
    #print("s = ", hex(s))

    # -- VERIFICACION --
    try:
        inicio =  default_timer()
        pubKE.verify(signature=ECC_s, data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
        fin =  default_timer()
        t_ecdsa571_v.append("{0:0.10f}".format(fin-inicio))
        #print("tiempo = %f" % (t_verificacion))
        #print("Las firmas coinciden")
    except(exceptions.InvalidSignature):
        #print("tiempo =-1")
        pass

def ecdsa521(msg):
    # -------------------------------------------------
    # ECDSA Prime Field
    # 512 bits - SHA 512 
    # q = 512 bits
    # -------------------------------------------------
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
    inicio =  default_timer()
    ECC_sign = privKECC.sign(data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
    fin =  default_timer()
    r,s = utils.decode_dss_signature(ECC_sign)
    t_ecdsa521_f.append("{0:0.10f}".format(fin-inicio))
    #print("tiempo = %f" % (t_firma))
    #print("r = {}".format(hex(s)))
    #print("s = {}".format(hex(r)))

    # -- VERIFICACION --
    try:
        inicio =  default_timer()
        pubKECC.verify(signature=ECC_sign, data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
        fin =  default_timer()
        t_ecdsa521_v.append("{0:0.10f}".format(fin-inicio))
        #print("tiempo = %f" % (t_verificacion))
    except(exceptions.InvalidSignature):
        #print("tiempo =-1")
        pass

def promedios(vector,tam):
    suma = 0
    for i in range(tam):
        suma = suma + float(vector[i])
    return suma/float(tam)

def grafico(f1,f2,f3,f4,v1,v2,v3,v4,c):
    """
    El orden de los vectores es:
    RSA, DSA, ECDSA Binario, ECDSA Primo
    """
    x=np.arange(100)
    #Convertir a numeros
    for i in range(c):
        f1[i] = float(f1[i])
        f2[i] = float(f2[i])
        f3[i] = float(f3[i])
        f4[i] = float(f4[i])
        v1[i] = float(v1[i])
        v2[i] = float(v2[i])
        v3[i] = float(v3[i])
        v4[i] = float(v4[i])
    fig, (ax1, ax2) = plt.subplots(1, 2)
    ax1.plot(x,f1, label='RSA')
    ax1.plot(x,f2, label='DSA')
    ax1.plot(x,f3, label='ECDSA Binario')
    ax1.plot(x,f4, label='ECDSA Primo')
    plt.legend()
    ax2.plot(x,v1, label='RSA')
    ax2.plot(x,v2, label='DSA')
    ax2.plot(x,v3, label='ECDSA Binario')
    ax2.plot(x,v4, label='ECDSA Primo')
    plt.legend()
    ax1.set_title("Grafíco de creación de firmas")
    ax2.set_title("Grafíco de verificación de firmas")
    plt.show()

#Vectores para tiempos
#firmas
t_rsapps_f = []
t_dsa1024_f = []
t_ecdsa571_f = []
t_ecdsa521_f = []
#verificación
t_rsapps_v = []
t_dsa1024_v = []
t_ecdsa571_v = []
t_ecdsa521_v = []

#contador de vectores
c = 0

#Lectura de archivo
for line in fileinput.input():
    msg = toBytes(line.strip('\n'))
    c = c + 1
    rsapps(msg)
    dsa1024(msg)
    ecdsa571(msg)
    ecdsa521(msg)

#Promedios
p_rsapps_f = promedios(t_rsapps_f,c)
p_dsa1024_f = promedios(t_dsa1024_f,c)
p_ecdsa571_f = promedios(t_ecdsa571_f,c)
p_ecdsa521_f = promedios(t_ecdsa521_f,c)
p_rsapps_v = promedios(t_rsapps_v,c)
p_dsa1024_v = promedios(t_dsa1024_v,c)
p_ecdsa571_v = promedios(t_ecdsa571_v,c)
p_ecdsa521_v = promedios(t_ecdsa521_v,c)

print("-----------------------------  FIRMA  ------------------------------")
print("Vector\tRSA PPS\t\tDSA\t\tECDSA Bin\tECDSA Prime")
for i in range(c):
    print(str(i+1) + "\t" + str(t_rsapps_f[i]) + "\t" + str(t_dsa1024_f[i]) + "\t" + str(t_ecdsa571_f[i]) + "\t" + str(t_ecdsa521_f[i]))
print("---------------------------------------------------------------------")
print("Prom:\t" + "{:.10f}".format(p_rsapps_f) + "\t{:.10f}".format(p_dsa1024_f) + "\t{:.10f}".format(p_ecdsa571_f) + "\t{:.10f}".format(p_ecdsa521_f))
print("#####################################################################\n\n")

print("--------------------------  VERIFICACIÓN  ---------------------------")
print("Vector\tRSA PPS\tDSA\tECDSA Bin\tECDSA Prime")
for i in range(c):
    print(str(i+1) + "\t" + str(t_rsapps_v[i]) + "\t" + str(t_dsa1024_v[i]) + "\t" + str(t_ecdsa571_v[i]) + "\t" + str(t_ecdsa521_v[i]))
print("---------------------------------------------------------------------")
print("Prom:\t" + "{:.10f}".format(p_rsapps_v) + "\t{:.10f}".format(p_dsa1024_v) + "\t{:.10f}".format(p_ecdsa571_v) + "\t{:.10f}".format(p_ecdsa521_v))
print("#####################################################################\n\n")

grafico(t_rsapps_f,t_dsa1024_f,t_ecdsa571_f,t_ecdsa521_f,t_rsapps_v,t_dsa1024_v,t_ecdsa571_v,t_ecdsa521_v,c)
#grafico(t_rsapps_v,t_dsa1024_v,t_ecdsa571_v,t_ecdsa521_v,c,"Verificación de Firmas")