# -------------------------------------------------
# SHA2-384 
# -------------------------------------------------
import hashlib 
  
# Mensaje al que se le aplicara una funcion hash
msg = "aa4"
msg_bytes=bytes(msg, 'utf-8')

# Hash de salida esperado
real_output_a="54A59B9F22B0B80880D8427E548B7C23ABD873486E1F035DCE9CD697E85175033CAA88E6D57BC35EFAE0B5AFD3145F31"

# Se aplica la funcion hash
program_output = hashlib.sha384(msg_bytes).hexdigest().upper()
  
print(program_output)
#print(len(program_output))

if (real_output_a == program_output):
	print("Successful exit")
else:
	print("Error")