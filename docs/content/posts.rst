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
the posts in their amended state, or use get_message and only get the unique POST
messages (with their content obviously).

Since version 0.8.0, get_posts uses a PostFilter object to specify the filters:

.. code-block:: python3

    >>> from aleph.sdk.chains.sol import get_fallback_account
    >>> from aleph.sdk.client import AuthenticatedAlephHttpClient
    >>> from aleph.sdk.posts import PostFilter
    >>> account = get_fallback_account()
    >>> async with AuthenticatedAlephHttpClient(account) as client:
    ...     posts, status = await client.get_posts(
    ...         post_filter=PostFilter(channel='MY_CHANNEL')
    ...     )


Creating a Post
---------------

Creating a post means creating a post object and wrapping it in a message.
There is an helper for that: create_post.

.. code-block:: python3

    >>> from aleph.sdk.chains.sol import get_fallback_account
    >>> from aleph.sdk.client import AuthenticatedAlephHttpClient
    >>> account = get_fallback_account()
    >>> async with AuthenticatedAlephHttpClient(account) as client:
    ...     post, status = await client.create_post({'content': 'test'}, post_type='testtype', channel='MY_CHANNEL')
    >>> message
    {
        'chain': 'SOL',
        'channel': 'MY_CHANNEL',
        'sender': '21hKNCB7xmDZ1pgteuJPbhKN1aDvsvPJRJ5Q95G5gyCW',
        'type': 'POST',
        'time': '2023-07-11T13:20:14.604485+00:00',
        'item_content': '{"type":"testtype","address":"21hKNCB7xmDZ1pgteuJPbhKN1aDvsvPJRJ5Q95G5gyCW","content":{"content":"test"},"time":1573570575.2818618}',
        'content': {
            'type': 'testtype',
            'address': '21hKNCB7xmDZ1pgteuJPbhKN1aDvsvPJRJ5Q95G5gyCW',
            'content': {
                'content': 'test'
            },
            'time': 1573570575.2818618
        },
        'item_hash': '02afdbf33ff2c6ddb46349298a4598a8801cec61dbaa8f3a17ba9d1ad6dd8cb1',
        'signature': 'G7yJjMCPgvX04Dd9rsz0oEuuRFa4PfuKAMOPA3Oblf6vd5YA1x15jvWLL2WycnnzYLEl0usjTiVxBl530ZOmYgw='
    }

Amending a Post
---------------

Amending is as simple as creating a new post, but with two differences:

- The post_type must be 'amend'
- When calling create_post, you must pass the hash of the post you want to amend as 'ref'

Example:

.. code-block:: python3

    >>> from aleph.sdk.chains.sol import get_fallback_account
    >>> from aleph.sdk.client import AuthenticatedAlephHttpClient
    >>> account = get_fallback_account()
    >>> async with AuthenticatedAlephHttpClient(account) as client:
    ...     post, status = await client.create_post({'content': 'test2'}, post_type='amend', ref='02afdbf33ff2c6ddb46349298a4598a8801cec61dbaa8f3a17ba9d1ad6dd8cb1', channel='MY_CHANNEL')
    >>> message
    {
        'chain': 'SOL',
        'channel': 'MY_CHANNEL',
        'sender': '21hKNCB7xmDZ1pgteuJPbhKN1aDvsvPJRJ5Q95G5gyCW',
        'type': 'POST',
        'time': '2023-07-11T13:20:14.604485+00:00',
        'item_content': '{"type":"amend","address":"21hKNCB7xmDZ1pgteuJPbhKN1aDvsvPJRJ5Q95G5gyCW","content":{"content":"test2"},"time":1573570575.2818618,"ref":"02afdbf33ff2c6ddb46349298a4598a8801cec61dbaa8f3a17ba9d1ad6dd8cb1"}',
        'content': {
            'type': 'amend',
            'address': '21hKNCB7xmDZ1pgteuJPbhKN1aDvsvPJRJ5Q95G5gyCW',
            'content': {
                'content': 'test2'
            },
            'time': 1573570575.2818618,
            'ref': '02afdbf33ff2c6ddb46349298a4598a8801cec61dbaa8f3a17ba9d1ad6dd8cb1'
        },
        'item_hash': '02afdbf33ff2c6ddb46349298a4598a8801cec61dbaa8f3a17ba9d1ad6dd8cb1',
        'signature': 'G7yJjMCPgvX04Dd9rsz0oEuuRFa4PfuKAMOPA3Oblf6vd5YA1x15jvWLL2WycnnzYLEl0usjTiVxBl530ZOmYgw='
    }


.. note::

    More information on posts and messages in general can be found in the
    `pyaleph docs
    <https://pyaleph.readthedocs.io/en/latest/protocol/messages/post.html>`_.
