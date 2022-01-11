# publisher
from time import process_time
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secrets import token_bytes
import json

key = b'0123456789123456'

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
    client.on_message = on_message
    nonce, ciphertext, tag = encrypt(input())
    myDict = {'nonce': nonce, 'ciphertext':ciphertext, 'tag':tag }
    print(myDict)
    client.publish("Group4/test", str(myDict))
   