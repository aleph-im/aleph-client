import asyncio

from .test_app.main import app
from fastapi.testclient import TestClient


def test_app_event():

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


def test_app_http():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"index": "/"}
