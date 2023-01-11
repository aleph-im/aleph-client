""" Server metrics upload.
"""
# -*- coding: utf-8 -*-

import os
import platform
import time

import psutil

from aleph_client.chains.ethereum import get_fallback_account
from aleph_client.synchronous import create_aggregate


def get_sysinfo():
    uptime = int(time.time() - psutil.boot_time())
    sysinfo = {
        "uptime": uptime,
        "os": platform.platform(),
        "load_avg": os.getloadavg(),
        "num_cpus": psutil.cpu_count(),
    }

    return sysinfo


def get_memory():
    return psutil.virtual_memory()._asdict()


def get_swap_space():
    sm = psutil.swap_memory()
    swap = {
        "total": sm.total,
        "free": sm.free,
        "used": sm.used,
        "percent": sm.percent,
        "swapped_in": sm.sin,
        "swapped_out": sm.sout,
    }
    return swap


def get_cpu():
    return psutil.cpu_times_percent(0)._asdict()


def get_cpu_cores():
    return [c._asdict() for c in psutil.cpu_times_percent(0, percpu=True)]


def send_metrics(account, metrics):
    return create_aggregate(account, "metrics", metrics, channel="SYSINFO")


def collect_metrics():
    return {
        "memory": get_memory(),
        "swap": get_swap_space(),
        "cpu": get_cpu(),
        "cpu_cores": get_cpu_cores(),
    }


def main():
    account = get_fallback_account()
    while True:
        metrics = collect_metrics()
        message, status = send_metrics(account, metrics)
        print("sent", message.item_hash)
        time.sleep(10)


if __name__ == "__main__":
    main()
