from typing import Optional

from pydantic import BaseModel


class Message(BaseModel):
    chain: str
    channel: str
    sender: str
    type: str
    time: float

    item_content: Optional[str]
    item_hash: Optional[str]
