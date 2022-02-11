from aleph_client.vm.app import AlephApp
from fastapi import FastAPI

# Create a test app
http_app = FastAPI()
app = AlephApp(http_app=http_app)


@app.get("/")
async def index():
    return {"index": "/"}


@app.event(filters=[])
async def aleph_event(event):
    print("aleph_event", event)
