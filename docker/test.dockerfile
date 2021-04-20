FROM python:3.9

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     && rm -rf /var/lib/apt/lists/*

RUN mkdir /opt/aleph-client/
WORKDIR /opt/aleph-client/
COPY . .

RUN pip install -e .[testing,ethereum]
