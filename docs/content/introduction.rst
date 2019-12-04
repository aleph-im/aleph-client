Introduction to Aleph.im
========================

The Aleph.im network can be accessed from any API server.
To run one yourself, you will need to install
`PyAleph <https://github.com/aleph-im/PyAleph>`_.


Data retrieval
--------------

Data retrieval is simple, using ReST APIs on any API server.
There is a few helpers available in this library (depending on the requested
data type).


Data structures
---------------

All data transfered over the aleph.im network are aleph messages.

.. uml::

    @startuml
        entity Message {
            .. Message info ..
            *type : text
            one of: POST, AGGREGATE, STORE
            *channel : text
            (channel of the message, one application ideally has one channel)
            *time : timestamp
            .. Sender info ..
            *sender : text <<address>>
            *chain : text
            (chain of sender: NULS, NULS2, ETH, BNB...)
            -- Content --
            *item_hash <<hash>>
            if IPFS: multihash of json serialization of content
            if internal storage: hash of the content (sha256 only for now)
            if inline: hash of item_content using hash_type (sha256 only for now)
            *item_content : text <<json>>
            mandatory if of inline type, json serialization of the message
            #item_type : text (optional)
            one of: 'ipfs', 'inline', 'storage'.
            default: 'ipfs' if no item_content and hash length 56,
                     'storage' if length 64, 'inline' if there is an item_content.
            #hash_type : text (optional)
            default: sha256 (only supported value for now)
        }

        hide circle
    @enduml

Actual content sent by regular users can currently be of two types:

- AGGREGATE: a key-value storage specific to an address
- POST: unique data posts (unique data points, events

.. uml:: 
   
   @startuml
    object Message {
        ...
    }

    object Aggregate <<message content>> {
        key : text
        address : text <<address>>
        ~ content : object
        time : timestamp
    }

    object Post <<message content>> {
        type : text
        address : text <<address>>
        ~ content : object
        time : timestamp
    }

    object Store <<message content>> {
        address : text <<address>>
        item_type : same than Message.item_type
                    (note: does not support inline)
        item_hash : same than Message.item_hash
        time : timestamp
    }


    Message ||--o| Aggregate
    Message ||--o| Post
    Message ||--o| Store
   @enduml
