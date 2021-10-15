import asyncio

from aleph_client.vm.app import AlephApp


def test_app():

    # Create a test app
    app = AlephApp()

    @app.event(filters=[])
    async def aleph_event(event):
        print("aleph_event", event)

    # Call the app with an ASGI context
    scope = {
        "type": "aleph.message",
    }

    async def receive():
        return {"type": "aleph.message", "body": b"BODY", "more_body": False}

    send_queue: asyncio.Queue = asyncio.Queue()

    async def send(dico):
        await send_queue.put(dico)

    app(scope, receive, send)
