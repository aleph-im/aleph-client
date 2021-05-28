.. _posts:

========
Programs
========

Programs are special entries that define code to run on Aleph.im virtual machines.

Aleph.im currently supports programs written in Python that follow the
`ASGI interface <https://asgi.readthedocs.io/en/latest/introduction.html>`_.

In practice, the easiest approach is to use an
`ASGI compatible web framework <https://asgi.readthedocs.io/en/latest/implementations.html>`_,
such as
`FastAPI <https://fastapi.tiangolo.com/>`_ or
`Django <https://www.djangoproject.com/>`_.

Creating a program
------------------

Follow the `FastAPI Tutorial <https://fastapi.tiangolo.com/tutorial/>`_
to create your first program and test it using uvicorn.

Running on Aleph.im
-------------------

Use the :ref:`cli` to upload your program.

In this example, we will upload the
`example_fastapi_2 example from Aleph-VM
<https://github.com/aleph-im/aleph-vm/tree/main/examples/example_fastapi_2>`_.

.. code-block:: bash

    python3 -m aleph_client program /tmp/aleph-vm/examples/example_fastapi_2 __init__:app

The command will output two URLs:

- A URL link to see the message definition of your program
- A URL to run your program
