.. _posts:

========
Command-line Interface
========

Aleph-client can be used as a command-line interface to some Aleph.im
functionalities.

The following commands are available:

Post
----

Post a message on Aleph.im.

The content must be JSON encoded and is obtained either from a file
or from a user prompt.

.. code-block:: bash

    python3 -m aleph_client post [OPTIONS]

      Post a message on Aleph.im.

    Options:
      --path TEXT
      --type TEXT              [default: test]
      --channel TEXT           [default: TEST]
      --private-key TEXT
      --private-key-file TEXT
      --help                   Show this message and exit.


Upload
------

Upload and store a file on Aleph.im.

.. code-block:: bash

    python3 -m aleph_client upload [OPTIONS] PATH

      Upload and store a file on Aleph.im.

    Arguments:
      PATH  [required]

    Options:
      --channel TEXT           [default: TEST]
      --private-key TEXT
      --private-key-file TEXT
      --help                   Show this message and exit.

Pin
---

Persist a file from IPFS on Aleph.im.

.. code-block:: bash

    python3 -m aleph_client pin [OPTIONS] HASH

      Persist a file from IPFS on Aleph.im.

    Arguments:
      HASH  [required]

    Options:
      --channel TEXT           [default: TEST]
      --private-key TEXT
      --private-key-file TEXT
      --help                   Show this message and exit.

Program
-------

Register a program to run on Aleph.im virtual machines from a zip archive.

.. code-block:: bash

    python3 -m aleph_client program [OPTIONS] PATH ENTRYPOINT

      Register a program to run on Aleph.im virtual machines from a zip archive.

    Arguments:
      PATH        [required]
      ENTRYPOINT  [required]

    Options:
      --channel TEXT           [default: TEST]
      --private-key TEXT
      --private-key-file TEXT
      --help                   Show this message and exit.
