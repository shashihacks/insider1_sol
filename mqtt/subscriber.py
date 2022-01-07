# subscriber
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import json
from hashlib import sha256

key = b'0123456789123456'
testEncrypted = b'\x8f\t\xfb\xcf\xee\xa6SJ\xda\x910\xc5\xbb<\x88\x8e'

# public key - subscriber
n=0xa5da45a87c108ba666522d719bcc2806d397f8474573a2dba8f2c7b0bd772041f722f998657f0efa97e9d67b47a665216aec8e7b60dc57a10ee75619dd6959eaf079686781a6b2d7b5b68e13043c4885b70b6aa29c1da3818bcacb54ba5eac52bd574ab387b5b2379222cb3d6c72f35c57dbb73c59a968470c9addcb0a4f4331
e=0x10001





client = mqtt.Client()
client.connect('localhost', 9999)



def decrypt(nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('ascii')
    # try:
    #     cipher.verify(tag)
    #     return plaintext.decode('ascii')
    # except:
    #     return False



def on_connect(client, userdata, flags, rc):
    print("Connected to a broker!")
    client.subscribe("LINTANGtopic/verify")

def on_message(client, userdata, message):
    print("Message")
    print(message)
    print(message.payload)
    print(message.payload.decode())

    signature = message.payload.decode()
    print(signature)
    msg = b'A message for signing'
    hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
    hashFromSignature = pow(int(signature), e, n)
    print("Signature valid:", hash == hashFromSignature)
    # cipherObject = message.payload.decode()
    # cipherObject = eval(cipherObject)
    # print(cipherObject['ciphertext'])
    # plaintext = decrypt(cipherObject['nonce'], cipherObject['ciphertext'], cipherObject['tag'])
    # print(plaintext)
    # print(plaintext)


while True:
    client.on_connect = on_connect
    client.on_message = on_message
    client.loop_forever()