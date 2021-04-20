FROM python:3.9

# === Install IPFS ===
RUN apt-get install -y wget
RUN wget https://ipfs.io/ipns/dist.ipfs.io/go-ipfs/v0.7.0/go-ipfs_v0.7.0_linux-amd64.tar.gz
RUN tar -xvzf go-ipfs_v0.7.0_linux-amd64.tar.gz -C /opt/
RUN ln -s /opt/go-ipfs/ipfs /usr/local/bin/

# Volume to store IPFS data
RUN mkdir /var/lib/ipfs
ENV IPFS_PATH /var/lib/ipfs
VOLUME /var/lib/ipfs

# IPFS Swarm
EXPOSE 4001
# IPFS WebUI
EXPOSE 5001
# IPFS Gateway
EXPOSE 8080


# === Install Aleph-Client ===

RUN apt-get update && apt-get -y upgrade && apt-get install -y \
     libsecp256k1-dev \
     && rm -rf /var/lib/apt/lists/*

RUN mkdir /opt/aleph-client/
WORKDIR /opt/aleph-client/
COPY . .

RUN pip install -e .[testing,ethereum]


# - User 'aleph' to run the code itself
RUN useradd --create-home -s /bin/bash aleph
WORKDIR /home/aleph

COPY docker/with-ipfs.entrypoint.sh /entrypoint.sh
CMD ["/entrypoint.sh"]
