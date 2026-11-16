# Publication preparation — 0.7.5

Date: 2026-11-16. Author/copyright holder: Oleksandr, © 2026 Oleksandr.
Public contact: omtimemachineom@gmail.com.

The owner-provided Project Time Machine Non-Commercial License 1.0 is used in LICENSE.
Only an explicit Author line and text-file newline normalization were added to the
supplied text. The prior proposed project license is not included. Original third-party
license and NOTICE bytes are preserved, with attribution separate from project ownership.

The dependency review covers 23 runtime and three additional development packages,
using the pinned wheel metadata and upstream notices. Versions and license expressions
are recorded in third_party/dependency-inventory.json and THIRD_PARTY_NOTICES.md.
Certifi retains MPL-2.0 terms; no third-party package is relicensed as non-commercial.
Native binary subcomponents, OS images and tools need a separate inventory if binary
releases are later distributed. No binary dependencies or images are bundled here.

Public preparation changes only attribution, licensing, documentation, public packaging
inventories and removal of private historical-fixture paths from public test stubs.
Application runtime logic is preserved from 0.7.5. Existing source and installed copies
are not modified. No functional, integration, browser or deployment tests are rerun.

Checks for this preparation are limited to file inventory, license coverage, preserved
notice hashes, Python/shell syntax, local documentation links, packaging manifest,
known secret patterns and forbidden runtime artifacts. These checks are heuristic and
do not establish that every possible secret format is recognizable.

The repository is initialized locally on main with no imported development history,
no remote and no publication. Files are staged for owner review; no initial commit is
created automatically. All staged blobs and other locally present Git blobs are checked.
After future changes or commits, repeat the secret/history scan before publication.

Remaining publication decisions: choose the GitHub owner/repository name and explicitly
authorize publication. No GitHub URL or support response-time promise is invented.
Keep third-party review current when dependency pins change. The chosen license remains
Source-Available Non-Commercial; commercial permission is requested by email.
