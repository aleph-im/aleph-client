from typing import List

from aleph_message.models import AlephMessage
from pydantic import BaseModel


class MessagesResponse(BaseModel):
    """Response from an Aleph node API on the path /api/v0/messages.json"""

    messages: List[AlephMessage]
    pagination_page: int
    pagination_total: int
    pagination_per_page: int
    pagination_item: str
