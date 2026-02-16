# aleph-client

The official command-line interface (CLI) for [Aleph Cloud](https://www.aleph.cloud) — a decentralized cloud computing platform.

## What is Aleph Cloud?

Aleph Cloud provides decentralized computing, storage, and indexing services. With `aleph-client`, you can:

- **Deploy VMs (Instances)** — Run persistent virtual machines on decentralized infrastructure
- **Deploy Functions (Programs)** — Deploy serverless functions that scale automatically  
- **Store Data** — Upload files and data to decentralized storage
- **Send Messages** — Post, aggregate, and forget messages on the Aleph network
- **Manage Domains** — Configure custom domains for your deployments

## Quick Start

### Installation

```bash
# Install from PyPI
pip install aleph-client

# Verify installation
aleph --help
```

### Create Your First Instance

```bash
# Create a new account (generates keys)
aleph account create

# Deploy an Ubuntu instance with pay-as-you-go credits
aleph instance create --payment-type=credit --name="my-first-vm"

# List your instances
aleph instance list

# SSH into your instance
ssh root@<ipv6-address>
```

### Deploy a Serverless Function

```bash
# Create a simple FastAPI app
mkdir my-app && cd my-app
cat > main.py << 'EOF'
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def hello():
    return {"message": "Hello from Aleph Cloud!"}
EOF

# Deploy it
aleph program upload . main:app --name="my-function"
```

### Store Data

```bash
# Upload a file
aleph file upload myfile.txt

# Pin existing content by hash
aleph file pin QmYourContentHash
```

## Commands Overview

| Command | Description |
|---------|-------------|
| `aleph account` | Manage accounts and keys |
| `aleph instance` | Manage virtual machines (create, list, delete, logs) |
| `aleph program` | Deploy serverless functions |
| `aleph file` | Upload and manage files |
| `aleph message` | Send messages to the network |
| `aleph aggregate` | Manage key-value aggregates |
| `aleph domain` | Configure custom domains |
| `aleph node` | Interact with Compute Resource Nodes |
| `aleph credits` | Check credit balance |
| `aleph pricing` | View compute pricing |

Run `aleph <command> --help` for detailed usage of each command.

## Payment Options

Aleph Cloud supports multiple payment methods:

- **Credits (Pay-as-you-go)** — No token staking required, pay only for what you use
- **Hold** — Stake ALEPH tokens for allocation
- **Superfluid** — Stream payments for continuous services
- **NFT** — Use NFT vouchers for payment

## Documentation

- **Full Documentation**: https://docs.aleph.cloud/devhub/sdks-and-tools/aleph-cli/
- **API Reference**: https://docs.aleph.cloud/devhub/api/
- **Tutorials**: https://docs.aleph.cloud/devhub/tutorials/

## Requirements

### Linux

```bash
apt-get install -y python3-pip libsecp256k1-dev squashfs-tools
```

### macOS

```bash
brew tap cuber/homebrew-libsecp256k1
brew install libsecp256k1
```

### Windows

We recommend using [WSL](https://learn.microsoft.com/en-us/windows/wsl/install) (Windows Subsystem for Linux).

## Using Docker

Run the CLI without installing locally:

```bash
docker run --rm -ti -v $(pwd)/data:/data ghcr.io/aleph-im/aleph-client/aleph-client:master --help
```

Note: This uses an ephemeral key pair that is discarded when the container stops.

## Development

### Setup

We use [hatch](https://hatch.pypa.io/) for development:

```bash
pip install hatch
```

### Running Tests

```bash
hatch test
# or with coverage
hatch run testing:cov
```

### Code Quality

```bash
# Format code
hatch run linting:fmt

# Type checking
hatch run linting:typing
```

### Publishing

```bash
hatch build
hatch upload
```

## Additional Chains

For NULS2 support:

```bash
pip install aleph-sdk-python[nuls2]
```

## Contributing

Contributions are welcome! Please see our [contribution guidelines](CONTRIBUTING.md) and open a pull request.

## Links

- **Website**: https://aleph.cloud
- **Documentation**: https://docs.aleph.cloud
- **GitHub**: https://github.com/aleph-im
- **Discord**: https://discord.gg/aleph-im
- **Twitter**: https://twitter.com/alaboratory

## License

MIT License - see [LICENSE](LICENSE) for details.
