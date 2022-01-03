# subscriber
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import json

key = b'0123456789123456'
testEncrypted = b'\x8f\t\xfb\xcf\xee\xa6SJ\xda\x910\xc5\xbb<\x88\x8e'


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
    client.subscribe("LINTANGtopic/test")

def on_message(client, userdata, message):
    print("Message")
    print(message)
    print(message.payload)
    print(message.payload.decode())
    cipherObject = message.payload.decode()
    cipherObject = eval(cipherObject)
    print(cipherObject['ciphertext'])
    plaintext = decrypt(cipherObject['nonce'], cipherObject['ciphertext'], cipherObject['tag'])
    print(plaintext)
    # print(plaintext)


while True:
    client.on_connect = on_connect
    client.on_message = on_message
    client.loop_forever()