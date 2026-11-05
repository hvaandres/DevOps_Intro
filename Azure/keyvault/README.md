# Azure Key Vault scripts

The Make commands work directly from this directory. They use the interactive
tool in the sibling `../keyvault-cli` directory and its dedicated virtual environment.

```sh
make help
make setup
make doctor
make auth
make session
```

See the [complete Make command guide](../keyvault-cli/README.md) for every target,
service-principal authentication, named-vault operations, secret create/import/update,
request reports, permissions, troubleshooting, and credential-free dry-run testing.
Keep both directories together.

## Individual validation scripts

These remain available separately:

- `01_check_login.py`: service-principal token acquisition, optionally subscription access.
- `02_list_vaults.py`: vault names in a selected subscription.
- `03_check_vault.py`: data-plane connection and secret List permission.
- `04_list_secrets.py`: secret names, enabled state, and expiration; no values.
- `05_get_secret.py`: retrieval verification with hidden values, or explicit file/pipe output.

For standalone use, install `requirements.txt` in your own Python 3.10+ virtual
environment, or use `../keyvault-cli/.venv/bin/python` after `make setup`.
Each script accepts `--help`. The original scripts accept a subscription default
from `AZURE_SUBSCRIPTION_ID`; the Make CLI instead uses `SUBSCRIPTION`.

Never supply a client-secret value as an argument. Credentials use hidden input
or environment injection by a trusted secret manager. Authentication does not
modify your Azure CLI session. These five scripts are read-only; confirmed writes
are available through the Make CLI.
