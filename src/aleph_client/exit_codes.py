import os
from typing import Optional

import typer

# Aleph client exit codes
EX_NOFUNDS = 99

# Exit code to error message mapping
EXIT_CODE_MESSAGES = {
    os.EX_USAGE: "command line usage error",  # starts at 64
    os.EX_DATAERR: "data format error",
    os.EX_NOINPUT: "cannot open input",
    os.EX_NOUSER: "addressee unknown",
    os.EX_NOHOST: "host name unknown",
    os.EX_UNAVAILABLE: "service unavailable",
    os.EX_SOFTWARE: "internal software error",
    os.EX_OSERR: "system error (e.g., can't fork)",
    os.EX_OSFILE: "critical OS file missing",
    os.EX_CANTCREAT: "can't create (user) output file",
    os.EX_IOERR: "input/output error",
    os.EX_TEMPFAIL: "temp failure; user is invited to retry",
    os.EX_PROTOCOL: "remote error in protocol",
    os.EX_NOPERM: "permission denied",
    os.EX_CONFIG: "configuration error",  # ends at 78
    EX_NOFUNDS: "insufficient funds",
}


def exit_with_error_message(exit_code: int, message: Optional[str] = None) -> None:
    """
    Exit the program with the given exit code and print the corresponding error message.
    """
    error_message = EXIT_CODE_MESSAGES.get(exit_code, "unknown error")
    if message:
        typer.echo(f"{error_message}: {message}")
    else:
        typer.echo(error_message)
    typer.Exit(exit_code)
