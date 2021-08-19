# -------------------------------------------------
# SHA2-512 
# -------------------------------------------------
import hashlib 
  
# Mensaje al que se le aplicara una funcion hash
msg_a = format(ord("a"),"x")
msg_bytes=bytes.fromhex(msg_a)

# Hash de salida esperado
real_output_a="1F40FC92DA241694750979EE6CF582F2D5D7D28E18335DE05ABC54D0560E0F5302860C652BF08D560252AA5E74210546F369FBBBCE8C12CFC7957B2652FE9A75"

# Se aplica la funcion hash
program_output = hashlib.sha512(msg_bytes).hexdigest().upper()
  
#print(program_output)
#print(len(program_output))

if (real_output_a == program_output):
	print("Successful exit")
else:
	print("Error")
