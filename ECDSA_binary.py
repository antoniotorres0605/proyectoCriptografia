# -------------------------------------------------
# ECDSA Binary Field 
# 571 bits - Koblitz Curve - SHA 512 
# q = 570 bits
# -------------------------------------------------

# --- BIBLIOTECAS NECESARIAS --

# ECDSA Binary Field 571 bits - Koblitz Curve - SHA 512 
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography import exceptions

# -- Medir tiempo
import time 

# ---- ALGORITMO -----

def ecdsa571(msg):
    
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

    inicio = time.time()
    ECC_s = privKE.sign(data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
    fin = time.time()
    t_firma = fin - inicio
    r,s = utils.decode_dss_signature(ECC_s)
    #print("r = ", hex(r))
    #print("s = ", hex(s))

    # -- VERIFICACION --
    try:
        inicio = time.time()
        pubKE.verify(signature=ECC_s, data=msg, signature_algorithm=ec.ECDSA(hashes.SHA512()))
        fin = time.time()
        t_verificacion = fin - inicio
        #print("tiempo = %f" % (t_verificacion))
        return t_firma,t_verificacion
        #print("Las firmas coinciden")
    except(exceptions.InvalidSignature):
        #print("tiempo =-1")
        return t_firma,-1