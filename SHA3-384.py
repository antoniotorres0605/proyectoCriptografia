# -------------------------------------------------
# SHA2-384 
# -------------------------------------------------
import hashlib 
  
# Mensaje al que se le aplicara una funcion hash
msg_a = format(ord("a"),"x")
msg_bytes=bytes.fromhex(msg_a)

# Hash de salida esperado
real_output_a="1815F774F320491B48569EFEC794D249EEB59AAE46D22BF77DAFE25C5EDC28D7EA44F93EE1234AA88F61C91912A4CCD9"

# Se aplica la funcion hash
program_output = hashlib.sha3_384(msg_bytes).hexdigest().upper()
  
print(program_output)
#print(len(program_output))

if (real_output_a == program_output):
	print("Successful exit")
else:
	print("Error")