#!/usr/bin/env python3
import json
import os
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="CRN List API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Path to the CRN list JSON file
CURRENT_DIR = Path(__file__).parent
CRN_LIST_PATH = CURRENT_DIR / "crn_list.json"


@app.get("/")
async def root():
    """Redirect to the CRNs endpoint."""
    return {"message": "CRN List Mocked API - Use /crns.json endpoint to get the CRN list"}


@app.get("/crns.json")
async def get_crn_list():
    """Return the CRN list from the JSON file."""
    try:
        with open(CRN_LIST_PATH) as f:
            crn_data = json.load(f)
            return crn_data
    except Exception as e:
        return {"error": f"Failed to load CRN list: {e!s}"}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="localhost", port=port)
