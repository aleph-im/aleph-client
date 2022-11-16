from unittest.util import strclass
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def message():
    return {"message": "tututu ... message going to Aleph"}


