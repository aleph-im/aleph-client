from abc import ABC


class QueryError(ABC, ValueError):
    """The result of an API query is inconsistent."""

    pass


class MessageNotFoundError(QueryError):
    """A message was expected but could not be found."""

    pass


class MultipleMessagesError(QueryError):
    """Multiple messages were found when a single message is expected."""

    pass


class BroadcastError(Exception):
    """
    Data could not be broadcast to the aleph.im network.
    """

    pass


class InvalidMessageError(BroadcastError):
    """
    The message could not be broadcast because it does not follow the aleph.im
    message specification.
    """

    pass
