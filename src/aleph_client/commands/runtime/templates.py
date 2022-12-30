from .utils import (
    get_repo_latest_version,
    download_tmp_file,
    extract_archive_to_dir
)

BASE_SDK_URL = f"https://github.com/AmozPay/aleph-runtime-sdk"

def download_templates(dest: str, version: str):
    if version == "latest":
        version = get_repo_latest_version(BASE_SDK_URL)
    plugins_tgz = download_tmp_file(f"{BASE_SDK_URL}/releases/download/{version}/plugins_template.tar.gz")
    runtime_tgz = download_tmp_file(f"{BASE_SDK_URL}/releases/download/{version}/aleph-debian-11-python-base.tar.gz")
    extract_archive_to_dir(plugins_tgz, f"{dest}/plugins")
    extract_archive_to_dir(runtime_tgz, f"{dest}/aleph-debian-11-python-base")



if __name__ == "__main__":
    download_templates(".", "v0.0.1")