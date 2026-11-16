# Contributing

Contact: omtimemachineom@gmail.com. Please discuss substantial changes before submitting.
Contributions must respect Project Time Machine Non-Commercial License 1.0 in LICENSE.
Submit only code you have the right to contribute, identify authors and material changes,
and preserve third-party notices. Submission does not transfer third-party ownership or
establish a separate commercial permission. Do not add dependencies without recording
their version, upstream source, license and full notices in third_party/.

Use Python 3.11–3.13 on Linux and a separate environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -B scripts/run_tests.py --public
```

All tests must use disposable projects, databases and ports. Never test restore on a
working project. Two historical private-fixture cases are skipped in public tests;
no private fixtures are distributed. Test passwords and tokens are synthetic fixtures.
Keep code/config/state separate, metadata-only snapshots honest and all four locale
key sets equal. Do not weaken path, CSRF, ACL, confirmation or integrity checks.
Never execute monitored project code or automatically fix/restore it during audit.

Build a clean local candidate with `python -B scripts/build_release.py --output dist`.
Scan with `python -B scripts/build_release.py --scan . --history`. Recheck dependencies
and notices whenever requirements change. The heuristic scan is not proof that every
possible secret can be recognized. CI runs checks only; publication needs owner approval.
