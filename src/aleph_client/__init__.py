from importlib.metadata import PackageNotFoundError, version

try:
    # Change here if project is renamed and does not equal the package name
    __version__ = version("aleph-client")
except PackageNotFoundError:
    __version__ = "unknown"

# Deprecation check
moved_types = ["__version__", "AlephClient", "AuthenticatedAlephClient", "synchronous", "asynchronous"]


def __getattr__(name):
    if name in moved_types:
        raise ImportError(
            f"The 'aleph_client.{name}' type is deprecated and has been removed from aleph_client. Please use `aleph.sdk.{name}` instead."
        )
