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
    pricing,
    program,
)
from aleph_client.utils import AsyncTyper

app = AsyncTyper(no_args_is_help=True)

app.add_typer(account.app, name="account", help="Manage accounts")
app.add_typer(
    message.app,
    name="message",
    help="Manage messages (post, amend, watch and forget) on aleph.im & twentysix.cloud",
)
app.add_typer(
    aggregate.app, name="aggregate", help="Manage aggregate messages and permissions on aleph.im & twentysix.cloud"
)
app.add_typer(files.app, name="file", help="Manage files (upload and pin on IPFS) on aleph.im & twentysix.cloud")
app.add_typer(program.app, name="program", help="Manage programs (micro-VMs) on aleph.im & twentysix.cloud")
app.add_typer(instance.app, name="instance", help="Manage instances (VMs) on aleph.im & twentysix.cloud")
app.add_typer(domain.app, name="domain", help="Manage custom domain (DNS) on aleph.im & twentysix.cloud")
app.add_typer(node.app, name="node", help="Get node info on aleph.im & twentysix.cloud")
app.add_typer(about.app, name="about", help="Display the informations of Aleph CLI")
app.command("pricing")(pricing.prices_for_service)

if __name__ == "__main__":
    app()
