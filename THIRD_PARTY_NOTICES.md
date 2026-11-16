# Third-party notices

Project Time Machine author: Oleksandr. Third-party authors retain all rights in their
components; these are not works authored by Oleksandr or relicensed under the project's
non-commercial license. The following inventory covers all 23 pinned runtime packages
and all three additional development packages in requirements.lock/requirements-dev.txt.
Review date: 2026-11-16. Exact wheel METADATA and unmodified license/NOTICE texts were
inspected; artifact SHA-256 and upstream metadata are in dependency-inventory.json.
No dependency code, wheel, interpreter or OS image is bundled in this source repository.

| Package | Version | License | Use | Original notices |
| --- | --- | --- | --- | --- |
| aiofiles | 25.1.0 | Apache-2.0 | runtime | [LICENSE](third_party/licenses/aiofiles/licenses/LICENSE), [NOTICE](third_party/licenses/aiofiles/licenses/NOTICE) |
| annotated-doc | 0.0.6 | MIT | runtime | [LICENSE](third_party/licenses/annotated-doc/licenses/LICENSE) |
| annotated-types | 0.8.0 | MIT | runtime | [LICENSE](third_party/licenses/annotated-types/licenses/LICENSE) |
| anyio | 4.16.0 | MIT | runtime | [LICENSE](third_party/licenses/anyio/licenses/LICENSE) |
| argon2-cffi | 25.1.0 | MIT | runtime | [LICENSE](third_party/licenses/argon2-cffi/licenses/LICENSE) |
| argon2-cffi-bindings | 26.1.0 | MIT | runtime | [LICENSE](third_party/licenses/argon2-cffi-bindings/licenses/LICENSE) |
| certifi | 2026.10.23 | MPL-2.0 | development | [LICENSE](third_party/licenses/certifi/licenses/LICENSE) |
| cffi | 2.1.1 | MIT-0 | runtime | [LICENSE](third_party/licenses/cffi/licenses/LICENSE) |
| click | 8.5.1 | BSD-3-Clause | runtime | [LICENSE.txt](third_party/licenses/click/licenses/LICENSE.txt) |
| cryptography | 46.0.7 | Apache-2.0 OR BSD-3-Clause | runtime | [LICENSE](third_party/licenses/cryptography/licenses/LICENSE), [LICENSE.APACHE](third_party/licenses/cryptography/licenses/LICENSE.APACHE), [LICENSE.BSD](third_party/licenses/cryptography/licenses/LICENSE.BSD) |
| fastapi | 0.162.4 | MIT | runtime | [LICENSE](third_party/licenses/fastapi/licenses/LICENSE) |
| h11 | 0.16.0 | MIT | runtime | [LICENSE.txt](third_party/licenses/h11/licenses/LICENSE.txt) |
| httpcore | 1.0.9 | BSD-3-Clause | development | [LICENSE.md](third_party/licenses/httpcore/licenses/LICENSE.md) |
| httpx | 0.28.1 | BSD-3-Clause | development | [LICENSE.md](third_party/licenses/httpx/licenses/LICENSE.md) |
| idna | 3.20 | BSD-3-Clause | runtime | [LICENSE.md](third_party/licenses/idna/licenses/LICENSE.md) |
| Jinja2 | 3.1.6 | BSD-3-Clause | runtime | [LICENSE.txt](third_party/licenses/Jinja2/licenses/LICENSE.txt) |
| MarkupSafe | 3.0.4 | BSD-3-Clause | runtime | [LICENSE.txt](third_party/licenses/MarkupSafe/licenses/LICENSE.txt) |
| opentelemetry-api | 1.45.2 | Apache-2.0 | runtime | [LICENSE](third_party/licenses/opentelemetry-api/licenses/LICENSE) |
| pycparser | 3.12 | BSD-3-Clause | runtime | [LICENSE](third_party/licenses/pycparser/licenses/LICENSE) |
| pydantic | 2.14.3 | MIT | runtime | [LICENSE](third_party/licenses/pydantic/licenses/LICENSE) |
| pydantic_core | 2.50.4 | MIT | runtime | [LICENSE](third_party/licenses/pydantic_core/licenses/LICENSE) |
| python-multipart | 0.0.33 | Apache-2.0 | runtime | [LICENSE.txt](third_party/licenses/python-multipart/licenses/LICENSE.txt) |
| starlette | 1.10.0 | BSD-3-Clause | runtime | [LICENSE.md](third_party/licenses/starlette/licenses/LICENSE.md) |
| typing_extensions | 4.16.0 | PSF-2.0 | runtime | [LICENSE](third_party/licenses/typing_extensions/licenses/LICENSE) |
| typing-inspection | 0.4.5 | MIT | runtime | [LICENSE](third_party/licenses/typing-inspection/licenses/LICENSE) |
| uvicorn | 0.54.0 | BSD-3-Clause | runtime | [LICENSE.md](third_party/licenses/uvicorn/licenses/LICENSE.md) |

## Distribution obligations and scope

Retain the exact copyright/license texts supplied by each upstream project. Retain
Apache notices, including aiofiles NOTICE. Permissive dependencies do not become
non-commercial merely because the application has that restriction. No project-owned
code is represented as MIT/GPL licensed. BSD-3-Clause attribution and non-endorsement
conditions, MIT/MIT-0 notices, Apache-2.0 terms and PSF-2.0 notices remain applicable.
Cryptography offers Apache-2.0 OR BSD-3-Clause; both supplied texts are preserved.

Certifi is a development dependency under MPL-2.0. Its covered files retain MPL terms,
including source-availability obligations if those files or binaries are redistributed;
the application license does not override them. No certifi files are bundled here.
See the [Mozilla MPL FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/) and
[license text](https://www.mozilla.org/en-US/MPL/2.0/).

Python/pip/venv, uv, operating-system packages, Docker, container base images and GitHub
Actions are external tools, not vendored dependencies in this source distribution.
Native wheels may themselves contain OpenSSL, Argon2, libffi or Rust components; the
Python-package inventory is not a complete binary-image SBOM. If publishing wheels,
standalone executables or container images, separately inventory their transitive native
components and retain all notices and required source offers. Installation fetches
upstream dependencies under their own licenses; it does not grant new rights over them.

No conflict requiring removal of a declared Python dependency was identified for this
source-only distribution. This conclusion is limited to the pinned packages and supplied
texts; it does not assert exhaustive clearance of future binaries or all platforms.
