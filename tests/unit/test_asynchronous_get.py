from dis import code_info
import pytest
from aleph_message.models import MessageType, MessagesResponse
import time
from typing import Dict 

from aleph_message.models import MessageType, MessagesResponse, PostMessage, PostContent, ProgramMessage, ForgetMessage, AlephMessage
from aleph_message.models import AggregateMessage, AggregateContent, StoreMessage, StoreContent, ItemType, ForgetContent
from build.lib.aleph_client import conf
from aleph_message.models.program import Encoding, MachineType, ProgramContent, CodeContent, FunctionTriggers
from aleph_message.models.program import FunctionEnvironment, MachineResources, FunctionRuntime, MachineVolume
from aleph_client.chains.common import get_fallback_private_key, delete_private_key_file
from aiohttp.client import ClientSession

from aleph_client.asynchronous import (
    get_messages,
    fetch_aggregates,
    fetch_aggregate,
    _get_fallback_session,
    create_post,
    create_aggregate,
    create_store,
    create_program,
    forget,
    submit
)

from aleph_client.chains.ethereum import ETHAccount, get_fallback_account
from aleph_client.types import StorageEnum

@pytest.mark.asyncio
async def test_fetch_aggregate():
    _get_fallback_session.cache_clear()

    response = await fetch_aggregate(
        address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10", 
        key="corechannel"
    )
    assert response.keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_fetch_aggregates():
    _get_fallback_session.cache_clear()

    response = await fetch_aggregates(
        address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10"
    )
    assert response.keys() == {"corechannel"}
    assert response["corechannel"].keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_get_posts():
    _get_fallback_session.cache_clear()

    response: MessagesResponse = await get_messages(
        pagination=2,
        message_type=MessageType.post,
    )

    messages = response.messages
    assert len(messages) > 1
    for message in messages:
        assert message.type == MessageType.post


@pytest.mark.asyncio
async def test_get_messages():
    _get_fallback_session.cache_clear()

    response: MessagesResponse = await get_messages(
        pagination=2,
    )

    messages = response.messages
    assert len(messages) > 1
    assert messages[0].type
    assert messages[0].sender

@pytest.mark.asyncio
async def test_create_post():
    delete_private_key_file()

    _get_fallback_session.cache_clear()
    
    account: ETHAccount() = get_fallback_account()
    post_content : PostContent = (
        "ALEPH IN PARIS"
    )
    
    response: PostMessage = await create_post(
        account,
        post_content,
        post_type = "ok",
        ref = "02932831278",
        # address = conf.settings.ADDRESS_TO_USE,
        # channel = conf.settings.DEFAULT_CHANNEL,
        api_server = conf.settings.API_HOST,
        inline = True, 
    )
    
    content = response.content
    assert content.type == "ok"
    assert content.content == "ALEPH IN PARIS"
    assert content.time <= time.time()
    assert content.ref == "02932831278"
        
       
@pytest.mark.asyncio
async def test_create_aggregate():
    delete_private_key_file()

    _get_fallback_session.cache_clear()
    account: ETHAccount = get_fallback_account()
    
    agg_content : AggregateContent = (
        "0xa1B3b",
        {"Hello":"World"}
    )
    
    key = agg_content[0]
    content = agg_content[1]

    response: AggregateMessage = await create_aggregate(
        account = account,
        key = key,
        content = content
    )
    
    
    content = response.content
    assert content.key == "0xa1B3b"
    assert content.content == {"Hello":"World"}
    assert content.time <= time.time()
    

@pytest.mark.asyncio
async def test_create_store():
    delete_private_key_file()

    _get_fallback_session.cache_clear()
    
    account: ETHAccount = get_fallback_account()
    
    content : StoreContent = (
        ItemType.ipfs,
        "1291272085159665688"
    )
    
    item_type = content[0]
    item_hash = content[1]
    
    response: StoreMessage = await create_store(
        account,
        address = conf.settings.ADDRESS_TO_USE,
        file_hash = "0x1",
        channel = conf.settings.DEFAULT_CHANNEL,
        api_server = conf.settings.API_HOST,
        storage_engine = StorageEnum.ipfs
    )
    
    content = response.content
    assert content.item_type == item_type
    assert content.item_hash == "0x1"
    # assert len(content) > 200
    

@pytest.mark.asyncio
async def test_create_program():
    delete_private_key_file()

    
    _get_fallback_session.cache_clear()
    account: ETHAccount = get_fallback_account()
    
    content : ProgramContent(
        MachineType.vm_function
    )
    runtime_default ="bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
    runtime = "random"

    
    response : ProgramMessage = await create_program(
        account = account, 
        program_ref = "XX",
        entrypoint = "01",
        runtime = runtime,
        storage_engine = StorageEnum.ipfs,
        channel = conf.settings.DEFAULT_CHANNEL,
        api_server = conf.settings.API_HOST,
        memory =  conf.settings.DEFAULT_VM_MEMORY,
        vcpus = conf.settings.DEFAULT_VM_VCPUS,
        timeout_seconds = conf.settings.DEFAULT_VM_TIMEOUT,
        encoding = "zip"
        # volumes = 
    )
    
    content = response.content
    assert content.type == MachineType.vm_function
    assert content.allow_amend == False
    assert content.code == CodeContent(encoding = "zip", entrypoint = "01", ref= "XX", use_latest = True)
    # assert content.data == 
    assert content.on == FunctionTriggers(http = True)
    assert content.environment == FunctionEnvironment(reproducible = False, internet = True, aleph_api = True)
    assert content.resources == MachineResources(
        vcpus = conf.settings.DEFAULT_VM_VCPUS,
        memory = conf.settings.DEFAULT_VM_MEMORY,
        seconds = conf.settings.DEFAULT_VM_TIMEOUT)
    assert content.runtime == FunctionRuntime(
        ref = runtime,
        use_latest = True,
        comment = ""
    )
    
    assert type(content.volumes) == list
    
        
@pytest.mark.asyncio
async def test_forget():
    
    delete_private_key_file()

    
    _get_fallback_session.cache_clear()
    account: ETHAccount = get_fallback_account()
    
    FC : ForgetContent = (
        ["FAKE-HAS"],
        []
    )
    
    response : ForgetMessage = await forget(
        account = account,
        hashes = FC[0],
        storage_engine = StorageEnum.ipfs,
        channel = conf.settings.DEFAULT_CHANNEL,
        api_server = conf.settings.API_HOST
    )
    
    content = response.content 
    
    assert content.hashes == FC[0]
    assert content.aggregates == FC[1]
