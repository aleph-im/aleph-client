from aleph_message.models import MessageType, MessagesResponse

from aleph_client.conf import settings
from aleph_client.synchronous import get_messages
from aleph_client.types import Account
from aleph_client.user_session import UserSession


def test_get_posts(ethereum_account: Account):
    with UserSession(account=ethereum_account, api_server=settings.API_HOST) as session:
        response: MessagesResponse = get_messages(
            session=session,
            pagination=2,
            message_type=MessageType.post,
        )

        messages = response.messages
        assert len(messages) > 1
        for message in messages:
            assert message.type == MessageType.post
