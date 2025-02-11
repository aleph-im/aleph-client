import platform
import subprocess

from fastapi import FastAPI

app = FastAPI()

extra_checks = {
    "Docker": "docker --version",
    "Nodejs": "node --version",
    "Rust": "rustc --version",
    "Go": "go version",
}


@app.get("/")
async def versions() -> dict[str, str]:
    results = {}

    # Distribution
    try:
        results["Distribution"] = platform.freedesktop_os_release()["PRETTY_NAME"]  # type: ignore
    except Exception:
        results["Distribution"] = "Not available"

    # Python
    results["Python"] = platform.python_version()

    # Others
    for label, command in extra_checks.items():
        try:
            results[label] = subprocess.check_output(command.split(" ")).decode("utf-8").strip()
        except Exception:
            results[label] = "Not installed"

    return results
