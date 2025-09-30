maybe # CRN List API

A simple FastAPI application that serves the CRN list from a local JSON file.

## Setup

1. Install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Run the API server:

```bash
cd scripts/api/crn_list
python crn_list.py
```

The server will start on port 8000 by default. You can specify a different port using the `PORT` environment variable:

```bash
PORT=8080 python crn_list.py
```

## Usage

- The CRN list is available at: http://localhost:8000/crns.json
- Documentation is available at: http://localhost:8000/docs

## Configuring the Aleph Client SDK

To make the Aleph client SDK use your local CRN list API instead of the production one, set the following environment variable:

```bash
export CRN_LIST_URL=http://localhost:8000/crns.json
```

## Modifying the CRN List

To add or update test nodes in the CRN list, simply edit the `crn_list.json` file. The API will serve the updated content without requiring a restart.