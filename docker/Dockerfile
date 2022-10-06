FROM python:3.9-bullseye
MAINTAINER The aleph.im project

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     && rm -rf /var/lib/apt/lists/*

RUN useradd -s /bin/bash --create-home user
RUN mkdir /opt/venv
RUN mkdir /opt/aleph-client/
RUN chown user:user /opt/venv
RUN chown user:user /opt/aleph-client

USER user
RUN python3.9 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip wheel twine

# Preinstall dependencies for faster steps
RUN pip install --upgrade secp256k1 coincurve aiohttp eciespy python-magic typer
RUN pip install --upgrade 'aleph-message~=0.2.3' eth_account pynacl base58
RUN pip install --upgrade pytest pytest-cov pytest-asyncio mypy types-setuptools pytest-asyncio fastapi requests

WORKDIR /opt/aleph-client/
COPY . .
USER root
RUN chown -R user:user /opt/aleph-client

RUN pip install -e .[testing,ethereum,solana]

RUN mkdir /data
RUN chown user:user /data
ENV ALEPH_PRIVATE_KEY_FILE=/data/secret.key

WORKDIR /home/user
USER user
RUN aleph --install-completion bash
ENTRYPOINT ["aleph"]
CMD ["--help"]
