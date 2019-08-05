""" This is the simplest aleph network client available.
"""
from binascii import hexlify
import time
import requests
import json
import hashlib

DEFAULT_SERVER = "https://apitest.aleph.im"



def ipfs_push(content, api_server=DEFAULT_SERVER):
    resp = requests.post("%s/api/v0/ipfs/add_json" % api_server,
                         data=json.dumps(content))
    return resp.json().get('hash')


def broadcast(message, api_server=DEFAULT_SERVER):
    resp = requests.post("%s/api/v0/ipfs/pubsub/pub" % api_server,
                         json={'topic': 'ALEPH-TEST',
                               'data': json.dumps(message)})
    return resp.json().get('value')


def create_post(account, post_content, post_type, address=None,
                channel='TEST',  api_server=DEFAULT_SERVER):
    if address is None:
        address = account.get_address()

    post = {
        'type': post_type,
        'address': address,
        'content': post_content,
        'time': time.time()
    }
    return submit(account, post, 'POST', channel=channel,
                  api_server=api_server)


def create_aggregate(account, key, content, address=None,
                     channel='TEST', api_server=DEFAULT_SERVER):
    if address is None:
        address = account.get_address()

    post = {
        'key': key,
        'address': address,
        'content': content,
        'time': time.time()
    }
    return submit(account, post, 'AGGREGATE', channel=channel,
                  api_server=api_server)


def submit(account, content, message_type, channel='IOT_TEST',
           api_server=DEFAULT_SERVER, inline=True):

    
    message = {
      #'item_hash': ipfs_hash,
      'chain': account.CHAIN,
      'channel': channel,
      'sender': account.get_address(),
      'type': message_type,
      'time': time.time()
    }
    
    if inline:
        message['item_content'] = json.dumps(content, separators=(',',':'))
        h = hashlib.sha256()
        h.update(message['item_content'].encode('utf-8'))
        message['item_hash'] = h.hexdigest()
    else:
        message['item_hash'] = ipfs_push(content, api_server=api_server)
        
    message = account.sign_message(message)
    broadcast(message, api_server=api_server)
    return message


def fetch_aggregate(address, key, api_server=DEFAULT_SERVER):
    resp = requests.get("%s/api/v0/aggregates/%s.json?keys=%s" % (
        api_server, address, key
    ))
    return resp.json().get('data', dict()).get(key)
