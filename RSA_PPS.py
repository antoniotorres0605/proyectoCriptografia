#Algoritmo de firma digital
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
#tomar los tiempos de ejcución
from timeit import default_timer

random_generator = Crypto.Random.new().read # fuente segura de Entropía
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
