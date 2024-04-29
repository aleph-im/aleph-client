from pkg_resources import DistributionNotFound, get_distribution

try:
    # Change here if project is renamed and does not equal the package name
    dist_name = "aleph-client"
    __version__ = get_distribution(dist_name).version
except DistributionNotFound:
    __version__ = "unknown"
finally:
    del get_distribution, DistributionNotFound

# Deprecation check
moved_types = ["AlephClient", "AuthenticatedAlephClient", "synchronous", "asynchronous"]


def __getattr__(name):
    if name in moved_types:
        raise ImportError(
            f"The 'aleph_client.{name}' type is deprecated and has been removed from aleph_client. Please use `aleph.sdk.{name}` instead."
        )
