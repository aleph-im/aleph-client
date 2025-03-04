# Deprecation check
moved_types = ["__version__", "AlephClient", "AuthenticatedAlephClient", "synchronous", "asynchronous"]


def __getattr__(name):
    if name in moved_types:
        msg = (
            f"The 'aleph_client.{name}' type is deprecated and has been removed from "
            f"aleph_client. Please use `aleph.sdk.{name}` instead."
        )
        raise ImportError(msg)
