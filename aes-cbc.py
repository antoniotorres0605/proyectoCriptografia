# It is a mode of operation where each plaintext block gets XOR-ed with the previous ciphertext block prior to encryption.
import json
from base64 import b64encode
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

#CIFRADO

data = "014730f80ac625fe84f026c60bfd547d"
data = bytes.fromhex(data)
IV = "00000000000000000000000000000000"
IV = bytes.fromhex(IV)
key = "0000000000000000000000000000000000000000000000000000000000000000"
key = bytes.fromhex(key)

cipher = AES.new(key, AES.MODE_CBC, iv=IV)

ct_bytes = cipher.encrypt(pad(data, AES.block_size))
iv = b64encode(cipher.iv).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')

result = json.dumps({'iv':iv, 'ciphertext':ct})

print(ct)

b64 = json.loads(result)
iv = b64decode(b64['iv'])
ct = b64decode(b64['ciphertext'])
cipher = AES.new(key, AES.MODE_CBC, iv)


pt = unpad(cipher.decrypt(ct), AES.block_size)


print("The message was: ", pt.hex())