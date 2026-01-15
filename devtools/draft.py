import asyncio
import logging
from pathlib import Path

from run import MicroVM

logging.basicConfig(
    level=logging.DEBUG,
    format="%(relativeCreated)4f |V %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

vm = MicroVM(
    vm_id=0,
    firecracker_bin_path=Path("./bin/firecracker"),
    jailer_base_directory=Path("/tmp/jail"),
    use_jailer=False,
    jailer_bin_path=Path("./bin/release-v1.10.1-x86_64/jailer-v1.10.1-x86_64"),
    init_timeout=5.0,
    enable_log=True,
)

config_path = Path("utils/vm_config_base.json")
asyncio.run(vm.start(config_path))
