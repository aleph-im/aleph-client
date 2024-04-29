import jsonpickle
from typing import Any, Dict

from aleph_message.models import (
    AggregateMessage,
    ForgetMessage,
    MessageType,
    PostMessage,
    ProgramMessage,
    StoreMessage,
    InstanceMessage
)

from aleph_client.utils import get_message_type_value


def test_get_message_type_value():
    assert get_message_type_value(PostMessage) == MessageType.post
    assert get_message_type_value(AggregateMessage) == MessageType.aggregate
    assert get_message_type_value(StoreMessage) == MessageType.store
    assert get_message_type_value(ProgramMessage) == MessageType.program
    assert get_message_type_value(InstanceMessage) == MessageType.instance
    assert get_message_type_value(ForgetMessage) == MessageType.forget


def dump(target: Any):
    try:
        if isinstance(target, str):
            return target

        if isinstance(target, Dict):
            return str(target)

        return jsonpickle.encode(target, unpicklable=True, indent=2)
    except (Exception,):
        return target
