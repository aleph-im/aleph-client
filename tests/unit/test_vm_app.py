import asyncio

import pytest
from fastapi.testclient import TestClient

from tests.unit.test_app.main import app

# Note: for some reason, the test client must be declared at the same level as the import.
client = TestClient(app)


@pytest.mark.asyncio
async def test_app_event():

    # Call the app with an ASGI context
    scope = {
        "type": "aleph.message",
    }

    async def receive():
        return {"type": "aleph.message", "body": b"BODY", "more_body": False}

    send_queue: asyncio.Queue = asyncio.Queue()

    async def send(dico):
        await send_queue.put(dico)

    await app(scope, receive, send)


def test_app_http():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"index": "/"}
