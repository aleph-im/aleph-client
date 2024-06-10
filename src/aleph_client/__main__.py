"""
Aleph Client command-line interface.
"""

from aleph_client.commands import (
    about,
    account,
    aggregate,
    domain,
    files,
    instance,
    message,
    node,
    program,
)
from aleph_client.utils import AsyncTyper

app = AsyncTyper(no_args_is_help=True)

app.add_typer(account.app, name="account", help="Manage account")
app.add_typer(aggregate.app, name="aggregate", help="Manage aggregate messages on aleph.im")
app.add_typer(files.app, name="file", help="File uploading and pinning on IPFS and aleph.im")
app.add_typer(
    message.app,
    name="message",
    help="Post, amend, watch and forget messages on aleph.im",
)
app.add_typer(program.app, name="program", help="Upload and update programs on aleph.im VM")
app.add_typer(about.app, name="about", help="Display the informations of Aleph CLI")

app.add_typer(node.app, name="node", help="Get node info on aleph.im network")
app.add_typer(domain.app, name="domain", help="Manage custom Domain (dns) on aleph.im")
app.add_typer(instance.app, name="instance", help="Manage instances (VMs) on aleph.im network")

if __name__ == "__main__":
    app()
