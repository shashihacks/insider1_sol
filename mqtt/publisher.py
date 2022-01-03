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

while True:
    nonce, ciphertext, tag = encrypt(input())
    myDict = {'nonce': nonce, 'ciphertext':ciphertext, 'tag':tag }
    print(myDict)
    client.publish("LINTANGtopic/test", str(myDict))
   