""" Server metrics upload.
"""
# -*- coding: utf-8 -*-

import os
import psutil
# import requests
import platform
# import socket
import time
from aleph_client.main import create_aggregate, create_post

# from aleph_client.chains.nuls1 import NULSAccount, get_fallback_account
from aleph_client.chains.ethereum import ETHAccount, get_fallback_account


def get_sysinfo():
    uptime = int(time.time() - psutil.boot_time())
    sysinfo = {
        'uptime': uptime,
        # 'hostname': socket.gethostname(),
        'os': platform.platform(),
        'load_avg': os.getloadavg(),
        'num_cpus': psutil.cpu_count()
    }

    return sysinfo


def get_memory():
    return psutil.virtual_memory()._asdict()


def get_swap_space():
    sm = psutil.swap_memory()
    swap = {
        'total': sm.total,
        'free': sm.free,
        'used': sm.used,
        'percent': sm.percent,
        'swapped_in': sm.sin,
        'swapped_out': sm.sout
    }
    return swap


def get_cpu():
    return psutil.cpu_times_percent(0)._asdict()


def get_cpu_cores():
    return [c._asdict() for c in psutil.cpu_times_percent(0, percpu=True)]


def send_metrics(account, metrics):
    # metric_payload = {}
    return create_aggregate(account, 'metrics', metrics, channel='SYSINFO')


def collect_metrics():
    return {
        'memory': get_memory(),
        'swap': get_swap_space(),
        'cpu': get_cpu(),
        'cpu_cores': get_cpu_cores()
    }


def main():
    account = get_fallback_account()
    while True:
        metrics = collect_metrics()
        ret = send_metrics(account, metrics)
        print("sent", ret['item_hash'])
        time.sleep(10)


if __name__ == '__main__':
    main()
