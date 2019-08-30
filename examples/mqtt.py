""" Server metrics upload.
"""
# -*- coding: utf-8 -*-

import os
# import requests
import platform
# import socket
import time
import aiomqtt
import asyncio
import click
from aleph_client.main import create_aggregate, create_post

# from aleph_client.chains.nuls1 import NULSAccount, get_fallback_account
from aleph_client.chains.ethereum import ETHAccount
from aleph_client.chains.common import get_fallback_private_key


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


def on_disconnect(client, userdata, rc):
    if rc != 0:
        print("Unexpected MQTT disconnection. Will auto-reconnect")
        
    client.reconnect()
        
# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("/#")


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    # return create_aggregate(account, 'metrics', metrics, channel='SYSINFO')
    userdata['received'] = True
    state = userdata['state']
    parts = msg.topic.strip('/').split('/')
    curp = state
    for part in parts[:-1]:
        if not isinstance(curp.get(part, None), dict):
            curp[part] = {}
        curp = curp[part]
        
    curp[parts[-1]] = get_input_data(msg.payload)
    print(parts, msg.payload)
    
async def gateway(loop, host='api1.aleph.im', port=1883, ca_cert=None,
                  pkey=None, keepalive=10, transport='tcp', auth=None):
    
    if pkey is None:
        pkey = get_fallback_private_key()
        
    account = ETHAccount(private_key=pkey)
    state = dict()
    userdata = {'account': account, 'state': state, 'received': False}
    client = aiomqtt.Client(loop,
                            userdata=userdata,
                            transport=transport)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message
    
    if ca_cert is not None:
        client.tls_set(ca_cert)
    if auth is not None:
        client.username_pw_set(**auth)
        
    asyncio.ensure_future(client.loop_forever())

    await client.connect(host, port, keepalive)
    # client.loop_forever()
    while True:
        await asyncio.sleep(10)
        if not userdata['received']:
            await client.reconnect()
            
        for key, value in state.items():
            ret = create_aggregate(account, key, value, channel='IOT_TEST')
            print("sent", ret['item_hash'])
            userdata['received'] = False


@click.command()
@click.option('--host', default='localhost',
              help='MQTT Broker host')
@click.option('--port', default=1883, help='MQTT Broker port')
@click.option('--user', default=None, help='MQTT Auth username')
@click.option('--password', default=None, help='MQTT Auth password')
@click.option('--use-tls', is_flag=True)
@click.option('--ca-cert', default=None, help='CA Cert path')
@click.option('--pkey', default=None, help='Account private key (optionnal, will default to device.key file)')
def main(host, port, user, password, use_tls=False, ca_cert=None, pkey=None):
    loop = asyncio.get_event_loop()
    auth = None
    if user is not None:
        auth = {'username': user, 'password': password}
        
    if use_tls:
        if ca_cert is None:
            import certifi
            ca_cert = certifi.where()
            print(ca_cert)
        
    loop.run_until_complete(gateway(loop, host, port, ca_cert=ca_cert, pkey=pkey, auth=auth))


if __name__ == '__main__':
    main()