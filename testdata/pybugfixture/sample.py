import subprocess
import hashlib
import requests


def run_cmd(name):
    # shell=True with a built string is command-injection-prone
    subprocess.call("echo " + name, shell=True)


def digest(data):
    # MD5 is not safe for security use
    return hashlib.md5(data).hexdigest()


def fetch(url):
    # TLS verification disabled
    return requests.get(url, verify=False)


# Hard-coded credential
DB_PASSWORD = "s3cr3t"
