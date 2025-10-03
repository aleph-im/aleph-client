#!/usr/bin/python3
import ctypes
import sys
import time
from os import system

print("Hello from Python")
time.sleep(2)
print("Goodbye")

# Cleanup
system("umount /dev/shm")
system("umount /dev/pts")
system("umount -a")

# Send reboot syscall, see man page
# https://man7.org/linux/man-pages/man2/reboot.2.html
libc = ctypes.CDLL(None)
libc.syscall(169, 0xFEE1DEAD, 672274793, 0x1234567, None)
# The exit should not happen due to system halt.
sys.exit(0)
