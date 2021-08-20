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
import hashlib 
#Lectura de archivo
import fileinput
#Medir tiempo
from timeit import default_timer
#Impresión grafico
import numpy as np
import matplotlib.pyplot as plt 

#Tiempos de ejecución
t_sha2_384 = []
t_sha2_512 = []
t_sha3_384 = []
t_sha3_512 = []

#Contador de vectores
count = 0

def sha2_384(msg):
	# Se aplica la funcion hash SHA2 384
	inicio =  default_timer()
	program_output = hashlib.sha384(msg).hexdigest()
	fin =  default_timer()
	t_sha2_384.append("{0:0.10f}".format(fin-inicio))
	

def sha2_512(msg):
	# Se aplica la funcion hash SHA2 512
	inicio =  default_timer()
	program_output = hashlib.sha512(msg).hexdigest()
	fin =  default_timer()
	t_sha2_512.append("{0:0.10f}".format(fin-inicio))
	

def sha3_384(msg):
	# Se aplica la funcion hash SHA3 384
	inicio =  default_timer()
	program_output = hashlib.sha3_384(msg).hexdigest()
	fin =  default_timer()
	t_sha3_384.append("{0:0.10f}".format(fin-inicio))
	

def sha3_512(msg):
	# Se aplica la funcion hash SHA3 512
	inicio =  default_timer()
	program_output = hashlib.sha3_512(msg).hexdigest()
	fin =  default_timer()
	t_sha3_512.append("{0:0.10f}".format(fin-inicio))


def promedios(vector,tam):
    suma = 0
    for i in range(tam):
        suma = suma + float(vector[i])
    return suma/float(tam)	

def grafico(f1,f2,f3,f4):
    x=np.arange(100)
    #Convertir a numeros
    for i in range(count):
        f1[i] = float(f1[i])
        f2[i] = float(f2[i])
        f3[i] = float(f3[i])
        f4[i] = float(f4[i])
    fig, (ax1) = plt.subplots(1)
    ax1.plot(x,f1, label='SHA2 384')
    ax1.plot(x,f2, label='SHA2 512')
    ax1.plot(x,f3, label='SHA3 384')
    ax1.plot(x,f4, label='SHA3 512')
    plt.legend()
    ax1.set_title("Grafíco de Hashes")
    plt.show()
 

#Lectura de archivo
for line in fileinput.input():
    msg = bytes(line.strip('\n'), 'utf-8')
    sha2_384(msg)
    sha2_512(msg)
    sha3_384(msg)
    sha3_512(msg)
    count += 1

p_sha2_384 = promedios(t_sha2_384,count)  
p_sha2_512 = promedios(t_sha2_512,count)  
p_sha3_384 = promedios(t_sha3_384,count)  
p_sha3_512 = promedios(t_sha3_512,count)  

print("-----------------------------  Hashes  ------------------------------")
print("Vector\tSHA2 384\tSHA2 512\tSHA3 384\tSHA3 512")
for i in range(count):
    print(str(i+1) + "\t" + str(t_sha2_384[i]) + "\t" + str(t_sha2_512[i]) + "\t" + str(t_sha3_384[i]) + "\t" + str(t_sha3_512[i]))
print("---------------------------------------------------------------------")
print("Prom:\t" + "{:.10f}".format(p_sha2_384) + "\t{:.10f}".format(p_sha2_512) + "\t{:.10f}".format(p_sha3_384) + "\t{:.10f}".format(p_sha3_512))
print("#####################################################################\n\n")
grafico(t_sha2_384,t_sha2_512,t_sha3_384,t_sha3_512)