""" Server metrics upload.
"""
# -*- coding: utf-8 -*-

import os
import platform
import time

import psutil
from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.account import _load_account


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
    with AuthenticatedAlephClient(
        account=account, api_server="https://api2.aleph.im"
    ) as client:
        return client.create_aggregate("metrics", metrics, channel="SYSINFO")


def collect_metrics():
    return {
        "memory": get_memory(),
        "swap": get_swap_space(),
        "cpu": get_cpu(),
        "cpu_cores": get_cpu_cores(),
    }


def main():
    account = _load_account()
    while True:
        metrics = collect_metrics()
        message, status = send_metrics(account, metrics)
        print("sent", message.item_hash)
        time.sleep(10)


if __name__ == "__main__":
    main()
