from asyncio.events import get_event_loop
import logging
import asyncio
from asyncio.base_events import _run_until_complete_cb
from hbmqtt.broker import Broker
from hbmqtt.client import MQTTClient, ClientException
from hbmqtt.mqtt.constants import QOS_1
from Crypto.Cipher import AES
logger = logging.getLogger(__name__)
import paho.mqtt.client as mqtt

config = {
    'listeners': {
        'default': {
            'type': 'tcp',
            'bind': 'localhost:9999'    # 0.0.0.0:1883
        }
    },
    'sys_interval': 10,
    'topic-check': {
        'enabled': False
    },
    'plugins':['auth_anonymous'],
    'topic-check':{
        'enabled': True,
        'plugins':['topic_taboo']
    }
}

broker = Broker(config)

@asyncio.coroutine
def startBroker():
    print("start broker")
    yield from broker.start()





@asyncio.coroutine
def brokerGetMessage():
    C = MQTTClient()
    yield from C.connect('mqtt://localhost:9999/')
    
    print("inside subscription")
    yield from C.subscribe([
        ("LINTANGtopic/test", QOS_1),
        ("LINTANGtopic/verify", QOS_1)
    ])

   
    logger.info('Subscribed!')
    try:
        for i in range(1,100):
            message = yield from C.deliver_message()
            packet = message.publish_packet
            print(packet.payload.data.decode('utf-8'))
    except ClientException as ce:
        logger.error("Client exception : %s" % ce)
def __repr__(self): 
        return "Test" % (self) 

if __name__ == '__main__':
    
    formatter = "[%(asctime)s] :: %(levelname)s :: %(name)s :: %(message)s"
    logging.basicConfig(level=logging.INFO, format=formatter)
    
    asyncio.get_event_loop().run_until_complete(startBroker())

    asyncio.get_event_loop().run_until_complete(brokerGetMessage())

    asyncio.get_event_loop().run_forever()
     
