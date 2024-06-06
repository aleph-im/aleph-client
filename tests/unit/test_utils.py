from aleph_message.models import (
    AggregateMessage,
    ForgetMessage,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.models.base import MessageType

from aleph_client.utils import get_message_type_value


def test_get_message_type_value():
    assert get_message_type_value(PostMessage) == MessageType.post
    assert get_message_type_value(AggregateMessage) == MessageType.aggregate
    assert get_message_type_value(StoreMessage) == MessageType.store
    assert get_message_type_value(ProgramMessage) == MessageType.program
    assert get_message_type_value(ForgetMessage) == MessageType.forget
