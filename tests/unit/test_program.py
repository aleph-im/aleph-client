from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph.sdk.conf import settings
from pydantic import BaseModel

# Utils
settings.API_HOST = "https://api.twentysix.testnet.network"
