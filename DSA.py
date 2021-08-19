# -------------------------------------------------
# DSA 
# 1024 bits
# -------------------------------------------------

# --- BIBLIOTECAS NECESARIAS --

# -- DSA - 1024 bits
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# -- Medir tiempo
import time 

# ---- ALGORITMO -----

def dsa1024(msg):

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
    inicio = time.time()
    m = msg.encode("utf-8")
    hash_msg = SHA256.new(m)

    # -- FIRMA --
    sign = DSS.new(key, 'fips-186-3')
    s = sign.sign(hash_msg)
    fin = time.time()
    t_firma = fin - inicio
    
    # -- VERIFICACION --

    # -- Adecuación del mensaje
    inicio = time.time()
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
        fin = time.time()
        t_verificacion = fin - inicio
        #print ("La firma coincide")
        return t_firma,t_verificacion
    except ValueError:
        #print ("La firma no coincide")
        return t_firma,-1
