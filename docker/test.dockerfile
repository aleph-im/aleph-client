FROM python:3.9

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

# Preinstall dependencies for faster steps
RUN pip install --upgrade secp256k1 coincurve aiohttp eciespy
RUN pip install --upgrade pytest pytest-cov pytest-asyncio mypy python-magic types-setuptools
RUN pip install --upgrade 'aleph-message>=0.1.13' 'eth_account>=0.4.0'

RUN mkdir /opt/aleph-client/
WORKDIR /opt/aleph-client/
COPY . .

RUN pip install -e .[testing,ethereum]
