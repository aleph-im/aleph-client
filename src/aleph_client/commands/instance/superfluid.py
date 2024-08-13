import logging
from decimal import Decimal

from aleph.sdk.client.superfluid import SuperFluid
from eth_utils.currency import to_wei
from superfluid import Web3FlowInfo

logger = logging.getLogger(__name__)


def from_wei(wei_value: Decimal) -> Decimal:
    """Converts the given wei value to ether."""
    return wei_value / Decimal(10**18)


async def handle_flow(account: SuperFluid, sender: str, receiver: str, flow: Decimal):
    """
    Manages the flow of a Superfluid stream between a sender and receiver.

    This function checks the existing flow between the sender and receiver. If no flow
    exists, it creates a new flow with the specified rate. If a flow exists, it updates
    the flow by adding the specified flow rate to the current flow rate.

    :param account: The SuperFluid account instance used to interact with the blockchain.
    :param sender: Address of the sender in hexadecimal format.
    :param receiver: Address of the receiver in hexadecimal format.
    :param flow: The additional flow rate to be added (in ether).
    :return: The transaction hash of the executed operation (either create or update flow).
    """
    flow_info: Web3FlowInfo = await account.get_flow(sender, receiver)

    if not flow_info["flowRate"]:
        return await account.create_flow(sender, receiver, flow)
    else:
        current_flow_rate_wei = Decimal(flow_info["flowRate"])

        additional_flow_rate_wei = to_wei(flow, "ether")

        new_flow_rate_wei = current_flow_rate_wei + additional_flow_rate_wei

        new_flow_rate_ether = from_wei(new_flow_rate_wei)

        return await account.update_flow(sender, receiver, new_flow_rate_ether)


async def handle_flow_reduction(account: SuperFluid, sender: str, receiver: str, removed_flow: Decimal):
    """
    Reduces or deletes the flow between sender and receiver based on removed_flow.

    :param account: The SuperFluid account instance
    :param sender: Address of the sender
    :param receiver: Address of the receiver
    :param removed_flow: The flow rate to be removed (in ether)
    :return: The transaction hash of the executed operation or a status message
    """
    # Retrieve current flow info
    flow_info: Web3FlowInfo = await account.get_flow(sender, receiver)

    # Check if there is an existing flow
    if flow_info["flowRate"]:
        current_flow_rate_wei = Decimal(flow_info["flowRate"])
        removed_flow_rate_wei = to_wei(removed_flow, "ether")

        # Calculate the new flow rate
        new_flow_rate_wei = current_flow_rate_wei - removed_flow_rate_wei

        if new_flow_rate_wei > 0:
            # Update the flow with the reduced rate
            new_flow_rate_ether = from_wei(new_flow_rate_wei)
            return await account.update_flow(sender, receiver, new_flow_rate_ether)
        else:
            # Delete the flow as the new flow rate would be zero or negative
            return await account.delete_flow(sender, receiver)
