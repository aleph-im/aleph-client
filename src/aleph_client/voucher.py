import json
import logging
from decimal import Decimal
from typing import Optional, Union

import aiohttp
from aleph.sdk.client.http import AlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.query.filters import PostFilter
from aleph.sdk.query.responses import Post, PostsResponse
from aleph.sdk.types import Account
from aleph_message.models import Chain
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


VOUCHER_METDATA_TEMPLATE_URL = "https://claim.twentysix.cloud/sbt/metadata/{}.json"
VOUCHER_SOL_REGISTRY = "https://api.claim.twentysix.cloud/v1/registry/sol"
VOUCHER_SENDER = "0xB34f25f2c935bCA437C061547eA12851d719dEFb"


class VoucherAttribute(BaseModel):
    value: Union[str, Decimal]
    trait_type: str = Field(..., alias="trait_type")
    display_type: Optional[str] = Field(None, alias="display_type")


class VoucherMetadata(BaseModel):
    name: str
    description: str
    external_url: str = Field(..., alias="external_url")
    image: str
    icon: str
    attributes: list[VoucherAttribute]


class Voucher(BaseModel):
    id: str
    metadata_id: str = Field(..., alias="metadata_id")
    name: str
    description: str
    external_url: str = Field(..., alias="external_url")
    image: str
    icon: str
    attributes: list[VoucherAttribute]


class VoucherManager:
    def __init__(self, account: Optional[Account], chain: Optional[Chain]):
        self.account = account or None
        self.chain = chain or None

    def _resolve_address(self, address: Optional[str] = None) -> str:
        """
        Resolve the address to use. Prefer the provided address, fallback to account.
        """
        if address:
            return address
        if self.account:
            return self.account.get_address()
        error_msg = "No address provided and no account available to resolve address."
        raise ValueError(error_msg)

    async def _fetch_voucher_update(self):
        """
        Fetch the latest EVM voucher update (unfiltered).
        """
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            post_filter = PostFilter(types=["vouchers-update"], addresses=[VOUCHER_SENDER])
            vouchers_post: PostsResponse = await client.get_posts(post_filter=post_filter, page_size=1)
            if not vouchers_post.posts:
                return []

            message_post: Post = vouchers_post.posts[0]
            nft_vouchers = message_post.content.get("nft_vouchers", {})
            return list(nft_vouchers.items())  # [(voucher_id, voucher_data)]

    async def _fetch_solana_voucher(self):
        """
        Fetch full Solana voucher registry (unfiltered).
        """
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(VOUCHER_SOL_REGISTRY) as resp:
                        if resp.status != 200:
                            return {}

                        try:
                            return await resp.json()
                        except aiohttp.client_exceptions.ContentTypeError:
                            text_data = await resp.text()
                            try:
                                return json.loads(text_data)
                            except json.JSONDecodeError:
                                return {}
                except Exception:
                    return {}
        except Exception:
            return {}

    async def get_all(self, address: Optional[str] = None) -> list[Voucher]:
        """
        Retrieve all vouchers for the account / specific adress, across EVM and Solana chains.
        """
        vouchers = []

        # Get EVM vouchers
        evm_vouchers = await self.get_evm_voucher(address=address)
        vouchers.extend(evm_vouchers)

        # Get Solana vouchers
        solana_vouchers = await self.fetch_solana_vouchers(address=address)
        vouchers.extend(solana_vouchers)

        return vouchers

    async def fetch_vouchers_by_chain(self, chain: Chain):
        if chain == Chain.SOL:
            return await self.fetch_solana_vouchers()
        else:
            return await self.get_evm_voucher()

    async def get_evm_voucher(self, address: Optional[str] = None) -> list[Voucher]:
        """
        Retrieve vouchers specific to EVM chains for a specific address.
        """
        resolved_address = self._resolve_address(address=address)
        vouchers: list[Voucher] = []

        nft_vouchers = await self._fetch_voucher_update()
        for voucher_id, voucher_data in nft_vouchers:
            if voucher_data.get("claimer") != resolved_address:
                continue

            metadata_id = voucher_data.get("metadata_id")
            metadata = await self.fetch_metadata(metadata_id)
            if not metadata:
                continue

            voucher = Voucher(
                id=voucher_id,
                metadata_id=metadata_id,
                name=metadata.name,
                description=metadata.description,
                external_url=metadata.external_url,
                image=metadata.image,
                icon=metadata.icon,
                attributes=metadata.attributes,
            )
            vouchers.append(voucher)
        return vouchers

    async def fetch_solana_vouchers(self, address: Optional[str] = None) -> list[Voucher]:
        """
        Fetch Solana vouchers for a specific address.
        """
        resolved_address = self._resolve_address(address=address)
        vouchers: list[Voucher] = []

        registry_data = await self._fetch_solana_voucher()

        claimed_tickets = registry_data.get("claimed_tickets", {})
        batches = registry_data.get("batches", {})

        for ticket_hash, ticket_data in claimed_tickets.items():
            claimer = ticket_data.get("claimer")
            if claimer != resolved_address:
                continue

            batch_id = ticket_data.get("batch_id")
            metadata_id = None

            if str(batch_id) in batches:
                metadata_id = batches[str(batch_id)].get("metadata_id")

            if metadata_id:
                metadata = await self.fetch_metadata(metadata_id)
                if metadata:
                    voucher = Voucher(
                        id=ticket_hash,
                        metadata_id=metadata_id,
                        name=metadata.name,
                        description=metadata.description,
                        external_url=metadata.external_url,
                        image=metadata.image,
                        icon=metadata.icon,
                        attributes=metadata.attributes,
                    )
                    vouchers.append(voucher)

        return vouchers

    async def fetch_metadata(self, metadata_id: str) -> Optional[VoucherMetadata]:
        """
        Fetch metadata for a given voucher.
        """
        url = f"https://claim.twentysix.cloud/sbt/metadata/{metadata_id}.json"
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(url) as resp:
                        if resp.status != 200:
                            return None
                        data = await resp.json()
                        return VoucherMetadata.model_validate(data)
                except Exception as e:
                    logger.error(f"Error fetching metadata: {e}")
                    return None
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return None
