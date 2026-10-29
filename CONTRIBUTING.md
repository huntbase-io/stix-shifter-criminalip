# Contributing to stix-shifter-criminalip

Thanks for your interest. Bug reports, mapping improvements, new lookups and
docs fixes are all welcome.

## Before you start

- For anything bigger than a small fix, open an issue first so we can agree on
  the approach.
- Security issues: do not open a public issue; see [SECURITY.md](SECURITY.md).
- This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Never commit API keys or responses that identify your own infrastructure.
  Sample responses under `tests/*/sample_responses/` should be trimmed and use
  public or documentation IP addresses and domains.

## Development setup

The connector is developed inside a stix-shifter checkout. CI uses Huntbase's
stix-shifter fork (`develop`) and Python 3.12.

```bash
git clone -b develop https://github.com/huntbase-io/stix-shifter.git
cd stix-shifter
python3 -m venv .venv && . .venv/bin/activate
python generate_requirements.py && pip install -r requirements-dev.txt
pip install -r /path/to/stix-shifter-criminalip/requirements-ci.txt

# Copy the module in. tests/utils skips symlinked modules, so use --copy
# before running it; a symlink install is fine for the connector tests.
/path/to/stix-shifter-criminalip/scripts/install_into_stix_shifter.sh --copy .
```

CI runs these checks on every pull request, from the stix-shifter checkout:

```bash
python -m pytest stix_shifter_modules/criminalip -q
python -m pytest tests/utils -q
flake8 stix_shifter_modules/criminalip --max-line-length=127
python map_validator/validate_mapping.py stix_shifter_modules/criminalip/stix_translation/json/to_stix_map.json
```

The unit tests make no network calls. The mapping validator must log no
`ERROR` lines.

## Pull requests

- Make changes in this repository's `stix_shifter_modules/criminalip/`, not
  in the copy inside stix-shifter.
- Keep each PR focused, with tests for behaviour changes.
- Update [the connector README](stix_shifter_modules/criminalip/README.md) and
  `criminalip_supported_stix.md` when you change mappings, operators or
  connection options.

Releases are cut by the maintainers from `v*` tags.

## Licence

By contributing you agree that your contributions are licensed under the
project's [Apache License 2.0](LICENSE).
