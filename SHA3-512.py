# -------------------------------------------------
# SHA3-512 
# -------------------------------------------------
import hashlib 
  
# Mensaje al que se le aplicara una funcion hash
msg_a = format(ord("a"),"x")
msg_bytes=bytes.fromhex(msg_a)

# Hash de salida esperado
real_output_a="697F2D856172CB8309D6B8B97DAC4DE344B549D4DEE61EDFB4962D8698B7FA803F4F93FF24393586E28B5B957AC3D1D369420CE53332712F997BD336D09AB02A"

# Se aplica la funcion hash
program_output = hashlib.sha3_512(msg_bytes).hexdigest().upper()
  
print(program_output)
#print(len(program_output))

if (real_output_a == program_output):
	print("Successful exit")
else:
	print("Error")