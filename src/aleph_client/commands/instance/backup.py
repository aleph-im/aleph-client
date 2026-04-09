from __future__ import annotations

import asyncio
import io
import json
import logging
from pathlib import Path
from typing import Annotated, Optional

import aiohttp
import typer
from aleph_message.models import Chain
from click import echo
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.prompt import Prompt

from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.conf import settings
from aleph_client.commands import help_strings
from aleph_client.commands.instance.network import find_crn_of_vm
from aleph_client.commands.utils import get_console, setup_logging, yes_no_input
from aleph_client.utils import AccountTypes, AsyncTyper, load_account, sanitize_url

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


class _ProgressFile(io.RawIOBase):
    """File wrapper that reports read progress to a Rich Progress bar."""

    def __init__(self, path: Path, progress: Progress, task_id):
        self._file = open(path, "rb")
        self._progress = progress
        self._task = task_id

    def read(self, size=-1):
        chunk = self._file.read(size)
        if chunk:
            self._progress.advance(self._task, len(chunk))
        return chunk

    def readinto(self, b):
        chunk = self._file.read(len(b))
        n = len(chunk)
        b[:n] = chunk
        if n:
            self._progress.advance(self._task, n)
        return n

    def readable(self):
        return True

    def writable(self):
        return False

    def seekable(self):
        return False

    def close(self):
        self._file.close()
        super().close()


async def resolve_crn_domain(domain: str | None, vm_id: str) -> str:
    """Resolve CRN domain from user input, allocation lookup, or interactive prompt."""
    return (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the VM is running")
    )


@app.command()
async def create(
    vm_id: Annotated[str, typer.Argument(help="VM item hash to back up")],
    include_volumes: Annotated[
        bool,
        typer.Option(
            "--include-volumes",
            help="Include persistent data volumes in the backup (default: rootfs only)",
        ),
    ] = False,
    follow: Annotated[
        bool,
        typer.Option(
            "--follow",
            help="Wait and poll until the backup completes",
        ),
    ] = False,
    skip_fsfreeze: Annotated[
        bool,
        typer.Option(
            "--skip-fsfreeze",
            help="Skip filesystem freeze (no consistency guarantee)",
        ),
    ] = False,
    domain: Annotated[
        Optional[str],
        typer.Option(help="CRN domain on which the VM is running"),
    ] = None,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_USED)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    as_json: Annotated[bool, typer.Option("--json", help="Print as json instead of rich output")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Create a backup of an instance.

    By default only the rootfs is backed up. Use --include-volumes to
    also include persistent data volumes in the tar archive.
    """

    setup_logging(debug)

    domain = await resolve_crn_domain(domain, vm_id)
    account: AccountTypes = load_account(private_key, private_key_file, chain=chain)

    async with VmClient(account, domain) as manager:
        console = get_console()

        status, result = await manager.create_backup(
            vm_id=vm_id,
            include_volumes=include_volumes,
            skip_fsfreeze=skip_fsfreeze,
        )

        if status == 202:
            if not follow:
                echo(f"Backup started. Check status with:\n\n  aleph instance backup info {vm_id}\n")
                return
            with console.status("Backup in progress..."):
                while status == 202:
                    await asyncio.sleep(5)
                    status, result = await manager.get_backup(vm_id=vm_id)

        if status != 200:
            echo(f"Backup failed (status {status}): {result}")
            raise typer.Exit(1)

        backup_info = json.loads(result)

        if as_json:
            echo(json.dumps(backup_info, indent=2))
            return

        console.print(f"Backup created successfully on CRN: {domain}")
        console.print(f"  Backup ID:    [bold]{backup_info.get('backup_id', 'N/A')}[/bold]")
        console.print(f"  Size:         {backup_info.get('size', 'N/A')} bytes")
        console.print(f"  Checksum:     {backup_info.get('checksum', 'N/A')}")
        console.print(f"  Expires at:   {backup_info.get('expires_at', 'N/A')}")
        download_url = backup_info.get("download_url")
        if download_url:
            console.print(f"  Download URL: [link={download_url}]{download_url}[/link]")
            console.print("\nTo download this backup:")
            console.print(f"  aleph instance backup download '{download_url}' -o backup.tar")


@app.command()
async def info(
    vm_id: Annotated[str, typer.Argument(help="VM item hash")],
    as_json: Annotated[bool, typer.Option("--json", help="Print as json")] = False,
    domain: Annotated[
        Optional[str],
        typer.Option(help="CRN domain on which the VM is running"),
    ] = None,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_USED)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Show info about the latest backup for an instance."""

    setup_logging(debug)

    domain = await resolve_crn_domain(domain, vm_id)
    account: AccountTypes = load_account(private_key, private_key_file, chain=chain)

    async with VmClient(account, domain) as manager:
        status, result = await manager.get_backup(vm_id=vm_id)

        if status == 202:
            echo("A backup is currently in progress.")
            return
        if status == 404:
            echo(f"No backup found. Create one with:\n\n  aleph instance backup create {vm_id}\n")
            return
        if status != 200:
            echo(f"Failed to get backup info (status {status}): {result}")
            raise typer.Exit(1)

        backup_info = json.loads(result)

        if as_json:
            echo(json.dumps(backup_info, indent=2))
            return

        console = get_console()
        console.print(f"Backup for instance [bold]{vm_id}[/bold]")
        console.print(f"  Backup ID:    [bold]{backup_info.get('backup_id', 'N/A')}[/bold]")
        console.print(f"  Size:         {backup_info.get('size', 'N/A')} bytes")
        console.print(f"  Checksum:     {backup_info.get('checksum', 'N/A')}")
        console.print(f"  Expires at:   {backup_info.get('expires_at', 'N/A')}")
        volumes = backup_info.get("volumes")
        if volumes:
            console.print(f"  Volumes:      {json.dumps(volumes)}")
        download_url = backup_info.get("download_url")
        if download_url:
            console.print(f"  Download URL: [link={download_url}]{download_url}[/link]")


async def _download_from_url(url: str, output: Path):
    """Stream a backup tar from a presigned URL with progress bar."""
    tmp = output.with_suffix(output.suffix + ".tmp")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    text = await response.text()
                    echo(f"Download failed (status {response.status}): {text}")
                    raise typer.Exit(1)

                total = response.content_length or 0
                with Progress(
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(),
                    DownloadColumn(),
                    TransferSpeedColumn(),
                    TimeRemainingColumn(),
                ) as progress:
                    task = progress.add_task(
                        f"Downloading to {output}",
                        total=total if total else None,
                    )
                    with open(tmp, "wb") as f:
                        async for chunk in response.content.iter_chunked(8192):
                            f.write(chunk)
                            progress.advance(task, len(chunk))
        tmp.rename(output)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    echo(f"Backup downloaded to {output}")


@app.command()
async def download(
    url: Annotated[Optional[str], typer.Argument(help="Presigned download URL from backup create")] = None,
    vm_id: Annotated[
        Optional[str],
        typer.Option("--vm-id", help="VM item hash to fetch latest backup for"),
    ] = None,
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output file path for the tar archive"),
    ] = Path("backup.tar"),
    domain: Annotated[
        Optional[str],
        typer.Option(help="CRN domain on which the VM is running"),
    ] = None,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_USED)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Download a backup archive.

    Provide either a presigned URL directly, or --vm-id to automatically
    fetch the latest backup's download URL from the CRN.
    """

    setup_logging(debug)

    if url and vm_id:
        echo("Error: provide either a URL or --vm-id, not both.")
        raise typer.Exit(1)
    if not url and not vm_id:
        echo("Error: provide a presigned URL or --vm-id.")
        raise typer.Exit(1)

    download_url = url
    if vm_id:
        domain = await resolve_crn_domain(domain, vm_id)
        account: AccountTypes = load_account(private_key, private_key_file, chain=chain)

        async with VmClient(account, domain) as manager:
            status, result = await manager.get_backup(vm_id=vm_id)

            if status == 202:
                echo("A backup is currently in progress. Please wait for it to complete and try again.")
                raise typer.Exit(1)
            if status == 404:
                echo(
                    "No backup found for this instance. "
                    "Create one first with:\n\n"
                    f"  aleph instance backup create {vm_id}\n"
                )
                raise typer.Exit(1)
            if status != 200:
                echo(f"Failed to get backup info (status {status}): {result}")
                raise typer.Exit(1)

            backup_info = json.loads(result)
            download_url = backup_info.get("download_url")
            if not download_url:
                echo("Backup exists but no download URL available.")
                raise typer.Exit(1)

            echo(f"Found backup {backup_info.get('backup_id', 'N/A')}")

    assert download_url is not None  # guaranteed by validation above
    await _download_from_url(download_url, output)


@app.command()
async def delete(
    vm_id: Annotated[str, typer.Argument(help="VM item hash")],
    backup_id: Annotated[str, typer.Argument(help="Backup ID to delete")],
    domain: Annotated[
        Optional[str],
        typer.Option(help="CRN domain on which the VM is running"),
    ] = None,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_USED)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Delete a backup archive."""

    setup_logging(debug)

    if not yes_no_input(f"Delete backup {backup_id}?", default=False):
        echo("Delete cancelled.")
        return

    domain = await resolve_crn_domain(domain, vm_id)
    account: AccountTypes = load_account(private_key, private_key_file, chain=chain)

    async with VmClient(account, domain) as manager:
        status, result = await manager.delete_backup(vm_id=vm_id, backup_id=backup_id)
        if status != 200:
            echo(f"Delete failed (status {status}): {result}")
            raise typer.Exit(1)

        echo(f"Backup {backup_id} deleted.")


@app.command()
async def restore(
    vm_id: Annotated[str, typer.Argument(help="VM item hash to restore")],
    rootfs_file: Annotated[
        Optional[Path],
        typer.Option("--file", "-f", help="Path to a QCOW2 rootfs image to upload"),
    ] = None,
    volume_ref: Annotated[
        Optional[str],
        typer.Option("--volume-ref", help="Aleph volume item hash to use as rootfs"),
    ] = None,
    domain: Annotated[
        Optional[str],
        typer.Option(help="CRN domain on which the VM is running"),
    ] = None,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_USED)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Restore a VM rootfs from a QCOW2 file or an Aleph volume reference.

    Provide exactly one of --file or --volume-ref. The VM will be stopped,
    the rootfs replaced, and the VM restarted.
    """

    setup_logging(debug)

    if rootfs_file and volume_ref:
        echo("Error: provide either --file or --volume-ref, not both.")
        raise typer.Exit(1)
    if not rootfs_file and not volume_ref:
        echo("Error: provide one of --file or --volume-ref.")
        raise typer.Exit(1)
    if rootfs_file and not rootfs_file.is_file():
        echo(f"Error: file not found: {rootfs_file}")
        raise typer.Exit(1)

    console = get_console()
    console.print(
        "[bold yellow]WARNING:[/bold yellow] This will replace the "
        "instance rootfs image.\n"
        "  - The VM will be stopped during restore\n"
        "  - The current rootfs will be [bold red]replaced[/bold red]\n"
        "  - Persistent data volumes will be [bold green]preserved[/bold green]"
    )

    if not yes_no_input("Proceed with restore?", default=False):
        echo("Restore cancelled.")
        return

    domain = await resolve_crn_domain(domain, vm_id)
    account: AccountTypes = load_account(private_key, private_key_file, chain=chain)

    async with VmClient(account, domain) as manager:
        if rootfs_file:
            try:
                url, header = await manager.get_restore_endpoint(vm_id=vm_id)
            except aiohttp.ClientError as e:
                echo(f"Failed to connect to CRN restore endpoint: {e}")
                raise typer.Exit(1) from e

            file_size = rootfs_file.stat().st_size

            with Progress(
                TextColumn("[bold blue]{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
            ) as progress:
                task = progress.add_task(f"Uploading {rootfs_file.name}", total=file_size)

                pf = _ProgressFile(rootfs_file, progress, task)
                data = aiohttp.FormData()
                data.add_field(
                    "rootfs",
                    pf,
                    filename=rootfs_file.name,
                    content_type="application/octet-stream",
                )
                try:
                    async with manager.session.post(url, headers=header, data=data) as response:
                        status = response.status
                        result = await response.text()
                finally:
                    pf.close()
        else:
            echo(f"Restoring from volume {volume_ref}...")
            status, result = await manager.restore_from_volume(vm_id=vm_id, volume_ref=volume_ref)

        if status != 200:
            echo(f"Restore failed (status {status}): {result}")
            raise typer.Exit(1)

        restore_info = json.loads(result)
        echo(f"VM restored on CRN: {domain}")
        old_backup = restore_info.get("old_rootfs_backup")
        if old_backup:
            echo(f"Old rootfs backed up at: {old_backup}")
