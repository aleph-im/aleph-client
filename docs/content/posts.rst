.. _posts:

=====
Posts
=====

Posts are unique data entries, that can be amended later on.
Example of use:

- Events
- Blog posts
- Comments
- and many more...

Getting posts
-------------

To get posts you have two options, either use the get_posts function, and get
the posts and their amends. Or use get_message and only get the unique POST
messages (with their content obviously).


Creating a Post
---------------

Creating a post means creating a post object and wrapping it in a message.
There is an helper for that: create_post.

.. code-block:: python3

    >>> from aleph_client.synchronous import create_post
    >>> create_post(account, {'content': 'test'}, post_type='testtype', channel='MY_CHANNEL')
    {'chain': 'NULS2',
     'channel': 'MY_CHANNEL',
     'sender': 'NULSd6HgaaV62iEcTZSWoaTrA3U7Jr7Vv1nXS',
     'type': 'POST',
     'time': 1573570575.281997,
     'item_content': '{"type":"testtype","address":"NULSd6HgaaV62iEcTZSWoaTrA3U7Jr7Vv1nXS","content":{"content":"test"},"time":1573570575.2818618}',
     'item_hash': '02afdbf33ff2c6ddb46349298a4598a8801cec61dbaa8f3a17ba9d1ad6dd8cb1',
     'signature': 'G7yJjMCPgvX04Dd9rsz0oEuuRFa4PfuKAMOPA3Oblf6vd5YA1x15jvWLL2WycnnzYLEl0usjTiVxBl530ZOmYgw='}


Asynchronous version is very similar:

.. code-block:: python3

    from aleph_client.asynchronous import create_post
    await create_post(...)

Amending a Post
---------------
