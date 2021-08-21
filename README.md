## Cifrado y Descrifrado

### Nombre del programa:  CifraDescifra.py

### Forma de ejecución
Es necesario pasarle como argumento al momento de la ejecución el archivo que contenga los vectores de mensaje, en nuestro caso se propone el archivo v_CifraDescrifra.txt, por lo que la ejecución sería de la siguiente manera:

    python CifraDescifra.py v_CifraDescifra.txt

El comando puede cambiar dependiendo del python instalado, en algunos casos puede ser necesario ejecutarlo de la siguiente manera:

    python3 CifraDescifra.py v_CifraDescifra.txt

Es importante mencionar que el archivo que lee tiene que tener las siguientes características:

- No contener caracteres especiales
- Separar los vectores de prueba con saltos de línea
- No ser un archivo vacío
- Tener los permisos necesarios para su ejecución (lectura)

El archivo que contiene de muestra contiene 100 vectores de diferentes tamaños, con el objetivo de poder analizar si dependiendo del tamaño del vector cambia el tiempo para el procesamiento del algoritmo

### Dependencias

Es necesario contar con las siguientes bibliotecas:

    base64
    binascii
    pycryptodome
    fileinput 
    timeit
    numpy
    json
    matplotlib

### Salida esperada

En la consola se aprecian los tiempos en forma de tabla de los algoritmos que componen este programa, al inicio de la tabla muestra el título del proceso que hace (Cifrado o Descifrado) asi como las cabeceras de los algoritmos, al final de cada tabla se puede ver el promedio obtenido por cada algoritmo.

De igual manera se mostrará una ventana emergente que muestra la gráfica comparativa de todos los algoritmos aplicados para el cifrado y en otro gráfico aplicados para descifrado que permite hacer una comparación gráfica de los tiempos necesarios para cada algoritmo

### Descripción

El programa se compone de las siguientes funciones:
- toBytes(m) el cual permite pasar cada mensaje a bytes para posteriormente ser procesados por los algoritmos
- aes_ecb(text) Es la función encargada del cifrado y descifrado para AES ECB, tiene como entrada el mensaje que se cifrara y permite añadir al vector global los tiempos que toma el cifrado y el descifrado para este algoritmo
- aes_cbc(text) Es la función encargada del cifrado y descifrado para AES CBC, tiene como entrada el mensaje que se cifrara y permite añadir al vector global los tiempos que toma el cifrado y el descifrado para este algoritmo
- rsa_oaep(message) Es la función encargada del cifrado y descifrado para RSA OAEP, tiene como entrada el mensaje que se cifrara y permite añadir al vector global los tiempos que toma el cifrado y el descifrado para este algoritmo
- promedios(vector,tam) permite obtener el promedio de un vector dado. Tiene como entrada el vector y el tamaño de este, su salida es el promedio obtenido
- gráfico(c1,c2,c3,d1,d2,d3,c) Permite la creación del gráfico de comparación del tiempo tomado para cada algoritmo por cada vector tanto para el cifrado como para el descifrado

A continuación se hace la lectura del archivo de entrada y por cada línea que lee se ejecutan todos los algoritmos.

Finalmente se hace la impresión de los resultados y de la gráfica

## Hash

### Nombre del programa: Hash.py

### Forma de ejecución

Es necesario pasarle como argumento al momento de la ejecución el archivo que contenga los vectores de mensaje, en nuestro caso se propone el archivo Hash.txt, por lo que la ejecución sería de la siguiente manera:

    python Hash.py Hash.txt

El comando puede cambiar dependiendo del python instalado, en algunos casos puede ser necesario ejecutarlo de la siguiente manera:

    python3 Hash.py Hash.txt

Es importante mencionar que el archivo que lee tiene que tener las siguientes características:

- No contener caracteres especiales
- Separar los vectores de prueba con saltos de línea
- No ser un archivo vacío
- Tener los permisos necesarios para su ejecución (lectura)

El archivo que contiene de muestra contiene 100 vectores de diferentes tamaños, con el objetivo de poder analizar si dependiendo del tamaño del vector cambia el tiempo para el procesamiento del algoritmo

### Dependencias

Es necesario contar con las siguientes bibliotecas:

    hashlib
    fileinput
    timeit
    numpy
    matplotlib

### Salida esperada

En la consola se aprecian los tiempos (en forma de tabla) de las funciones hash que componen este programa, al inicio de la tabla muestra el título del proceso que hace (Hash) así como los nombres de las funciones hash, al final de cada tabla se puede ver el promedio obtenido por cada función hash.

De igual manera se mostrará una ventana emergente que muestra la gráfica comparativa de todas las funciones hash que permite hacer una comparación gráfica de los tiempos necesarios para cada función hash.

### Descripción

El programa se compone de las siguientes funciones:

- sha2_384(msg): Función encargada de obtener el hash al mensaje usando la función hash SHA2 384.
- sha2_512(msg): Función encargada de obtener el hash al mensaje usando la función hash SHA2 512.
- sha2_384(msg): Función encargada de obtener el hash al mensaje usando la función hash SHA3 384.
- sha3_512(msg): Función encargada de obtener el hash al mensaje usando la función hash SHA3 512.
- promedios(vector,tam) permite obtener el promedio de un vector dado. Tiene como entrada el vector y el tamaño de este, su salida es el promedio obtenido.
- gráfico(f1,f2,f3,f4) Permite la creación del gráfico de comparación del tiempo tomado para cada función hash.

Después se hace la lectura del archivo de entrada y por cada línea que lee se ejecutan todas las funciones hash.

Finalmente se hace la impresión de los resultados y de la gráfica.



## Firma digital y verificación de firma

### Nombre del programa: FirmaVerificacion.py

### Forma de ejecución

Es necesario pasarle como argumento al momento de la ejecución el archivo que contenga los vectores de mensaje, en nuestro caso se propone el archivo v_FirmaVerificacion.txt, por lo que la ejecución sería de la siguiente manera:

    python FirmaVerificacion.py FirmaVerificacion.txt

El comando puede cambiar dependiendo del python instalado, en algunos casos puede ser necesario ejecutarlo de la siguiente manera:

    python3 FirmaVerificacion.py v_FirmaVerificacion.txt

Es importante mencionar que el archivo que lee tiene que tener las siguientes características:
- No contener caracteres especiales.
- Separar los vectores de prueba con saltos de línea.
- No ser un archivo vacío.
- Tener los permisos necesarios para su ejecución (lectura).

El archivo que contiene de muestra contiene 100 vectores de diferentes tamaños, con el objetivo de poder analizar si dependiendo del tamaño del vector cambia el tiempo para el procesamiento del algoritmo

### Dependencias

Es necesario contar con las siguientes bibliotecas:

    pycryptodome
    fileinput 
    timeit
    numpy
    cryptography
    matplotlib
    jwt

### Salida esperada

En la consola se aprecian los tiempos en forma de tabla de los algoritmos que componen este programa, al inicio de la tabla muestra el título del proceso que hace (Firma y Verificación de firma) así como las cabeceras de los algoritmos, al final de cada tabla se puede ver el promedio obtenido por cada algoritmo.

De igual manera se mostrará una ventana emergente que muestra la gráfica comparativa de todos los algoritmos aplicados para la firma y en otro gráfico aplicados para la verificación de firmas que permite hacer una comparación gráfica de los tiempos necesarios para cada algoritmo

### Descripción

El programa se compone de las siguientes funciones:

- toBytes(m) el cual permite pasar cada mensaje a bytes para posteriormente ser procesados por los algoritmos
- rsapps(m) Es la función encargada de la firma y la verificación de la misma para RSA PPS  tiene como entrada el mensaje que se firmara y permite añadir al vector global los tiempos que toma la firma y la comprobación de esta para este algoritmo
- dsa1024(msg) Es la función encargada de la firma y la verificación de la misma para DSA  tiene como entrada el mensaje que se firmara y permite añadir al vector global los tiempos que toma la firma y la comprobación de esta para este algoritmo
- ecdsa571(msg) Es la función encargada de la firma y la verificación de la misma para ECDSA Binary Field  tiene como entrada el mensaje que se firmara y permite añadir al vector global los tiempos que toma la firma y la comprobación de esta para este algoritmo
- ecdsa521(msg) Es la función encargada de la firma y la verificación de la misma para ECDSA Prime Field tiene como entrada el mensaje que se firmara y permite añadir al vector global los tiempos que toma la firma y la comprobación de esta para este algoritmo
promedios(vector,tam) permite obtener el promedio de un vector dado. Tiene como entrada el vector y el tamaño de este, su salida es el promedio obtenido
- gráfico(f1,f2,f3,f4,v1,v2,v3,v4,c) Permite la creación del gráfico de comparación del tiempo tomado para cada algoritmo por cada vector tanto para el cifrado como para el descifrado

A continuación se hace la lectura del archivo de entrada y por cada línea que lee se ejecutan todos los algoritmos.

Finalmente se hace la impresión de los resultados y de la gráfica.

