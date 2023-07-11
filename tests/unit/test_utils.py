from aleph_message.models import (
    AggregateMessage,
    ForgetMessage,
    MessageType,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)

from aleph_client.commands.utils import write_file_from_bytes
from aleph_client.utils import get_message_type_value


def test_get_message_type_value():
    assert get_message_type_value(PostMessage) == MessageType.post
    assert get_message_type_value(AggregateMessage) == MessageType.aggregate
    assert get_message_type_value(StoreMessage) == MessageType.store
    assert get_message_type_value(ProgramMessage) == MessageType.program
    assert get_message_type_value(ForgetMessage) == MessageType.forget


def test_write_file_from_bytes():
    path = "./file.txt"
    content = b"This is a Test file content."

    # Call the function
    write_file_from_bytes(path, content)

    # Check if the file was written correctly
    with open(path, "rb") as file:
        file_content = file.read()
    assert file_content == b"This is a Test file content."
