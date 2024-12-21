from aleph.sdk.chains.evm import EVMAccount

FAKE_PRIVATE_KEY = b"cafe" * 8
FAKE_PUBKEY_FILE = "/path/fake/pubkey"
FAKE_ADDRESS_EVM = "0x00001A0e6B9a46Be48a294D74D897d9C48678862"
FAKE_STORE_HASH = "102682ea8bcc0cec9c42f32fbd2660286b4eb31003108440988343726304607a"  # Needs to exist on Aleph Testnet


def create_test_account() -> EVMAccount:
    return EVMAccount(private_key=FAKE_PRIVATE_KEY)
