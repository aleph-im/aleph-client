""" Server metrics upload.
"""
# -*- coding: utf-8 -*-

import os
import psutil
# import requests
import platform
# import socket
import time
import aiomqtt
import asyncio
from aleph_client.main import create_aggregate, create_post

# from aleph_client.chains.nuls1 import NULSAccount, get_fallback_account
from aleph_client.chains.ethereum import ETHAccount, get_fallback_account

ACCOUNT = None

def get_input_data(value):
    if value == b'true':
        return True
    elif value == b'false':
        return False
    try:
        v = float(value)
        return v
    except ValueError:
        return value.decode('utf-8')

def send_metrics(account, metrics):
    # metric_payload = {}
    return create_aggregate(account, 'metrics', metrics, channel='SYSINFO')

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("/#")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    # return create_aggregate(account, 'metrics', metrics, channel='SYSINFO')
    state = userdata['state']
    parts = msg.topic.strip('/').split('/')
    curp = state
    for part in parts[:-1]:
        if not isinstance(curp.get(part, None), dict):
            curp[part] = {}
        curp = curp[part]
        
    curp[parts[-1]] = get_input_data(msg.payload)
    print(state)

async def main(loop):
    loop = asyncio.get_event_loop()
    account = get_fallback_account()
    state = dict()
    client = aiomqtt.Client(loop, userdata={'account': account, 'state': state})
    client.on_connect = on_connect
    client.on_message = on_message

    await client.connect("localhost", 1883, 60)
    client.loop_start()
    # client.loop_forever()
    while True:
        await asyncio.sleep(10)
        for key, value in state.items():
            ret = create_aggregate(account, key, value, channel='IOT_TEST')
            print("sent", ret['item_hash'])


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(loop))
