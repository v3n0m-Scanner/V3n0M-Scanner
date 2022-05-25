# Venom

![venom](../venom.png)

#### Offensive Security Tool for Vulnerability Scanning & Pentesting

![os](https://img.shields.io/badge/OS-Linux,%20Windows-green.svg)
[![pythonver](https://img.shields.io/badge/python-3.6%2B-green.svg)](https://www.python.org/downloads/release/python-3614)
[![License: GPLV3](https://img.shields.io/badge/License-GPLv3-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

#### Offensive Security Framework for Vulnerability Scanning & Pentesting

![os](https://img.shields.io/badge/OS-Linux,%20Windows-green.svg)
[![pythonver](https://img.shields.io/badge/python-3.6%2B-green.svg)](https://www.python.org/downloads/release/python-3614)
[![License: GPLV3](https://img.shields.io/badge/License-GPLv3-green.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Docker Pulls](https://img.shields.io/docker/pulls/vittring/venom.svg)](https://hub.docker.com/r/vittring/venom/)
[![Docker Image Size](https://img.shields.io/docker/image-size/vittring/venom.svg?sort=date)](https://hub.docker.com/r/vittring/venom/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

> **Warning**: Version 4.3.3 now requires PROXIES/VPN.

##### Features

- [x] USE PROXIES/VPN [Required]
- [x] Cloudflare Resolver [Cloudbuster]
- [x] LFI->RCE and XSS Scanning [LFI to RCE & XSS]
- [x] SQL Injection Vuln Scanner [SQLi]
- [x] Extremely Large D0rk Target Lists
- [x] Detects known WAFs
- [x] AdminPage Finding
- [x] CCTV/Networked Interfaces discovery [WIP] <<<<
- [x] Vulnerable FTPs Scanner [Toxin]
- [x] DNS Bruteforcer
- [x] Python 3.6 asyncio based scanning
- [x] Cloudflare resolver
- [x] Extremely quick "Toxin" Vulnerable IP scanner to scan potentially millions of ips for known vulnerable services.
- [x] Free and Open /src/
- [x] Cross-platform Python-based toolkit
- [x] Licensed under GPLv3
- [x] Built by hackers with full transparency
- [x] No more issues with dependencies from pre-alpha release

## Install from Docker Hub

Pull it from [Docker Hub](https://hub.docker.com/repository/docker/vittring/venom):

```bash
docker pull vittring/venom:devel
```

or build bleeding edge from here:

```bash
docker build -t vittring/venom:devel .
docker run --rm -ti vittring/venom:devel
```

## Docker Content Trust is enforced

I do not at present have a way to automate the process of signing the image, then
also signing with my GPG key, but maybe in the future. Content trust is disabled by
default in the Docker Client. To enable it, set the DOCKER_CONTENT_TRUST environment
variable to 1. This prevents users from working with tagged images unless they contain
a signature.

When DCT is enabled in the Docker client, docker CLI commands that operate on tagged
images must either have content signatures or explicit content hashes. The commands
that operate with DCT are [available here](https://docs.docker.com/engine/security/trust/).

Check the integrity of the container by running:
'''bash
docker trust inspect --pretty docker.io/vittring/venom:devel
'''

That's it!

## Credits to:

    - Architect for the initial encouragement and support in V3n0ms early days
    - SageHack for allowing Cloudbuster to be adapted for use within V3n0M
    - D35m0nd142 for allowing Collaboration and the use of LFI Suite within V3n0M
    - b4ltazar & all members of darkc0de.com for inspiring the project with darkd0rk3r

## Make Love and Smoke Trees.
