import logging
from decimal import Decimal
from enum import Enum

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.conf import settings
from click import echo
from eth_utils.currency import to_wei
from superfluid import Web3FlowInfo

logger = logging.getLogger(__name__)


def from_wei(wei_value: Decimal) -> Decimal:
    """Converts the given wei value to ether."""
    return wei_value / Decimal(10**settings.TOKEN_DECIMALS)


class FlowUpdate(str, Enum):
    REDUCE = "reduce"
    INCREASE = "increase"


async def update_flow(account: ETHAccount, receiver: str, flow: Decimal, update_type: FlowUpdate):
    """
    Update the flow of a Superfluid stream between a sender and receiver.
    This function either increases or decreases the flow rate between the sender and receiver,
    based on the update_type. If no flow exists and the update type is augmentation, it creates a new flow
    with the specified rate. If the update type is reduction and the reduction amount brings the flow to zero
    or below, the flow is deleted.

    :param account: The SuperFluid account instance used to interact with the blockchain.
    :param chain: The blockchain chain to interact with.
    :param receiver: Address of the receiver in hexadecimal format.
    :param flow: The flow rate to be added or removed (in ether).
    :param update_type: The type of update to perform (augmentation or reduction).
    :return: The transaction hash of the executed operation (create, update, or delete flow).
    """

    # Retrieve current flow info
    flow_info: Web3FlowInfo = await account.get_flow(receiver)

    current_flow_rate_wei: Decimal = Decimal(flow_info["flowRate"] or "0")
    flow_rate_wei: int = to_wei(flow, "ether")

    if update_type == FlowUpdate.INCREASE:
        if current_flow_rate_wei > 0:
            # Update existing flow by augmenting the rate
            new_flow_rate_wei = current_flow_rate_wei + flow_rate_wei
            new_flow_rate_ether = from_wei(new_flow_rate_wei)
            return await account.update_flow(receiver, new_flow_rate_ether)
        else:
            # Create a new flow if none exists
            return await account.create_flow(receiver, flow)
    elif update_type == FlowUpdate.REDUCE:
        if current_flow_rate_wei > 0:
            # Reduce the existing flow
            new_flow_rate_wei = current_flow_rate_wei - flow_rate_wei
            # Ensure to not leave infinitesimal flows
            # Often, there were 1-10 wei remaining in the flow rate, which prevented the flow from being deleted
            if new_flow_rate_wei > 99:
                new_flow_rate_ether = from_wei(new_flow_rate_wei)
                return await account.update_flow(receiver, new_flow_rate_ether)
            else:
                # Delete the flow if the new flow rate is zero or negative
                return await account.delete_flow(receiver)
        else:
            echo("No existing flow to stop. Skipping...")
