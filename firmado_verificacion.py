# -------------------------------------------------
# ECDSA Prime Field
# 512 bits - SHA 512 
# q = 512 bits
# -------------------------------------------------

# --- BIBLIOTECAS NECESARIAS --

# -- Algoritmos
from ECDSA_prime import ecdsa521
from ECDSA_binary import ecdsa571
from DSA import dsa1024

# --- LEER ARCHIVO DE VECTORES --

# -- Leer archivo 
i = 1
avgS_ECCP = 0
avgS_ECCB = 0
avgS_DSA = 0
avgV_ECCP = 0
avgV_ECCB = 0
avgV_DSA = 0
print (" No. Vector\tECDSA Prime 521b S-V\t\tECDSA Binary 571b S-V\t\tDSA - 1024b S-V")
with open("ECDSA_vectors.txt","r") as archivo:
    for linea in archivo:
        if "#" not in linea:

            # -- Codificacion mensaje
            msg = linea.encode("utf-8")
            
            # ---- ECDSA - Prime Field
            t_firma_prime,t_verificacion_prime = ecdsa521(msg)
            #print ("Vector %i\t T. Firma ECDSA_prime:%f\tT. Verificacion ECDSA_prime:%f\t\n" % (i,t_firma_prime,t_verificacion_prime))
            print(" Vector %i\t%f - %f\t" %(i,t_firma_prime,t_verificacion_prime),end='\t')
            avgS_ECCP += t_firma_prime
            avgV_ECCP += t_verificacion_prime
            
            # ---- ECDSA - Binary Field
            t_firma_bin,t_verificacion_bin = ecdsa571(msg)
            #print ("Vector %i\t T. Firma ECDSA_binary:%f\tT. Verificacion ECDSA_binary:%f\t\n" % (i,t_firma_bin,t_verificacion_bin))
            print("%f - %f\t" %(t_firma_bin,t_verificacion_bin),end='\t')
            avgS_ECCB += t_firma_prime
            avgV_ECCB += t_verificacion_prime

            # ---- DSA - 1024 bits
            t_firma_dsa,t_verificacion_dsa = dsa1024(linea)
            #print ("Vector %i\t T. Firma DSA:%f\tT. Verificacion DSA:%f\t\n" % (i,t_firma_dsa,t_verificacion_dsa))
            print("%f - %f\t" %(t_firma_dsa,t_verificacion_dsa))
            avgS_DSA += t_firma_prime
            avgV_DSA += t_verificacion_prime

            i += 1
    print(" Promedios:\t%f - %f\t\t%f - %f\t\t%f - %f" % (avgS_ECCP,avgV_ECCP, avgS_ECCB,avgV_ECCB,avgS_DSA,avgV_DSA))



