import pycurl
from sys import stderr as STREAM
import os
import pycurl
import tarfile
import subprocess

# callback function for c.XFERINFOFUNCTION
def status(download_t, download_d, upload_t, upload_d):
    kb = 1024
    STREAM.write('Downloading: {}/{} kiB ({}%)\r'.format(
        str(int(download_d/kb)),
        str(int(download_t/kb)),
        str(int(download_d/download_t*100) if download_t > 0 else 0)
    ))
    STREAM.flush()

def get_repo_latest_version(github_repo_url: str):
    c = pycurl.Curl()
    c.setopt(pycurl.FOLLOWLOCATION, True)
    c.setopt(pycurl.URL, f"{github_repo_url}/releases/latest")
    with open("/dev/null", "wb") as f:
        c.setopt(pycurl.WRITEFUNCTION, f.write)
        c.perform()
    version = os.path.basename(c.getinfo(pycurl.EFFECTIVE_URL))
    c.close()
    return version

def download_file(url: str, output: str):
    c = pycurl.Curl()
    c.setopt(pycurl.FOLLOWLOCATION, True)
    c.setopt(pycurl.URL, url)
    c.setopt(c.NOPROGRESS, False)
    c.setopt(c.XFERINFOFUNCTION, status)
    with open(output, "wb") as f:
        c.setopt(pycurl.WRITEFUNCTION, f.write)
        c.perform()
    c.close()

def download_tmp_file(url: str):
    c = pycurl.Curl()
    print(url)
    c.setopt(pycurl.FOLLOWLOCATION, True)
    c.setopt(pycurl.URL, url)
    # for some reason, tempdir module does not work. bash command does, so using subprocess here.
    tmp_name = subprocess.check_output(["mktemp", "/tmp/aleph-sdk-XXXX"]).decode("utf-8").strip()
    with open(tmp_name, "wb") as f:
        c.setopt(pycurl.WRITEFUNCTION, f.write)
        c.setopt(c.NOPROGRESS, False)
        c.setopt(c.XFERINFOFUNCTION, status)
        c.perform()
        c.close()
    return tmp_name

def extract_archive_to_dir(src: str, dest: str):
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(src) as tarf:
        tarf.extractall(dest)