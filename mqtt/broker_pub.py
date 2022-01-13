# publisher
from time import process_time
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import token_bytes
import json
import time
from hashlib import sha256

key = b'0123456789123456'

# private key
n= 0xa5da45a87c108ba666522d719bcc2806d397f8474573a2dba8f2c7b0bd772041f722f998657f0efa97e9d67b47a665216aec8e7b60dc57a10ee75619dd6959eaf079686781a6b2d7b5b68e13043c4885b70b6aa29c1da3818bcacb54ba5eac52bd574ab387b5b2379222cb3d6c72f35c57dbb73c59a968470c9addcb0a4f4331
d= 0x95cba6ce9dff73a23f1849e32a8c223ac831a214fd2d8c12496dbdde6bc1846910058ed98e124c3d19a822080696cb107bba5c9622cde0779f366215ca5cb4d080f24ae52b4f40d29d87f373de5b233005366a6d43956cc4a4945aa1d86eabd9b1b60e6d0720b9e4bb10c160c6aad9495ae641786f90435e02ae422706a2297

msg = b'A message for signing'
hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
signature = pow(hash, d, n)
print("Signature:", hex(signature))



def encrypt(msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('ascii'))
    return nonce, ciphertext, tag

client = mqtt.Client()
client.connect('localhost', 9999)



def on_message(client, userdata, message):
    print(message.payload.decode())
    print(client)
    print(userdata)



while True:
    # nonce, ciphertext, tag = encrypt(input())
    client.publish("Group4/verify", signature)
    time.sleep(1)
   