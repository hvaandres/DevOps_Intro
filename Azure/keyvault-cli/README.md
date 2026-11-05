# Key Vault terminal tool and Make commands

Manage Azure Public Cloud Key Vault secrets using an explicit service principal.
Run the same Make commands from either `Azure/keyvault-cli` or `Azure/keyvault`.
Keep these directories together: the CLI reuses `../keyvault/keyvault_common.py`.
The five original scripts remain independently usable.

## Quick start

Requires Python 3.10+, Make, and an interactive terminal. Azure CLI is not required.
Use a trusted local machine; do not run with shell tracing, a debugger, or session
recording when handling secret values.

```sh
make help
make setup
make doctor
make auth
make session
```

`setup` creates `keyvault-cli/.venv` and installs the requirements and Ruff there.
Make selects that environment automatically; activation is unnecessary. Setup
downloads packages and changes local derived files, but never calls Azure.
Rerunning setup installs any currently missing dependencies; it is not a lockfile.

On macOS, install Python 3.10+ with your approved package manager. If Make is
missing, install the Xcode command-line tools (`xcode-select --install`).
Doctor recommends actions but does not install software or repair configuration.

## Authentication

Both commands authenticate the service principal:

```sh
make auth
make login
```

Missing tenant/client UUIDs are prompted. Supply these non-secret identifiers
through the environment to avoid repeated prompts:

```sh
export AZURE_TENANT_ID="your-tenant-uuid"
export AZURE_CLIENT_ID="your-service-principal-client-uuid"
make auth
```

The client secret uses a hidden terminal prompt. For a trusted secret-manager
integration, `AZURE_CLIENT_SECRET` can be injected into the process environment.
Do not type its value into a shell command, `.env` file, or Make variable.
The tool does not automatically load `.env` files.

`auth` validates token acquisition. With `SUBSCRIPTION`, it also checks that the
selected subscription is accessible and enabled. Neither success proves secret
List, Get, or Set permission.

```sh
make auth SUBSCRIPTION="My Subscription"
```

Each Make invocation is a separate process and authenticates independently.
`auth`/`login` do not persist credentials, establish a reusable Azure CLI login,
or alter an existing personal login. Use `session` for one credential reused
in memory across operations. SDK access tokens may refresh during a long session.

## Selectors and files

Pass non-secret selectors as Make variables, or export them in your environment.
Quote names and paths containing spaces. Command-line Make assignments override
environment defaults. Clear an exported selector with an empty assignment, such
as `SECRET=`, to return to selection/prompting.

- `VAULT`: vault name, not URL. Omit it to select a subscription and vault.
- `SECRET`: secret name. Omit it to select an existing secret for retrieval, or
  enter a name during create/update.
- `SUBSCRIPTION`: exact subscription display name or UUID. Duplicate typed names
  are rejected; use a UUID or numbered selection.
- `RESOURCE_GROUP`: use with `SUBSCRIPTION` when `VAULT` is supplied to verify
  vault membership. Provide both or neither. Without a named vault, a
  subscription alone narrows the vault-selection menu.
- `INPUT_FILE`: create/update/session only; one regular, owner-owned UTF-8 file
  with no group/other access. Symlinks are refused. Newlines are preserved.
- `OUTPUT_FILE`: a new plaintext retrieval file, created with mode `0600`.
  Existing files and destination symlinks are refused.
- `REPORT_FILE`: a new JSON metadata report, created with mode `0600`.
  The parent directory must already exist.
- `ONLINE=1`: enables read-only Azure probes for `doctor`/`Doctor` only.
- `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`: non-secret service-principal UUIDs.

Make selectors are passed through the environment, not interpolated into shell
recipes. Never use Make variables for secret values. File paths still appear in
shell history, so use non-sensitive filenames.

Paths are relative to the directory where Make runs, not to `keyvault-cli`.
`make -C ../keyvault-cli ...` changes that base directory. The CLI supports Azure
Public Cloud only; sovereign-cloud endpoints are not configurable.

## Discovery, checks, and retrieval

### `make vaults`

List vault names and locations in one accessible subscription. Omit
`SUBSCRIPTION` to select it interactively. This is a control-plane operation;
it neither lists nor retrieves secret values.

```sh
make vaults SUBSCRIPTION="My Subscription"
```

### `make check`

Check data-plane connectivity and permission to list secret metadata. An empty
vault can pass this check. This does not test Get or Set permission.

```sh
make check VAULT="my-vault"
make check VAULT="my-vault" SUBSCRIPTION="My Subscription" RESOURCE_GROUP="my-rg"
```

### `make secrets`

List secret names and enabled flags without fetching values or exposing tags.

```sh
make secrets VAULT="my-vault"
```

### `make get`

Retrieve only the chosen secret's latest version. By default, select an output:

1. Verify retrieval and discard the value without displaying it.
2. Save the exact UTF-8 value to a new owner-only plaintext file.
3. Reveal a JSON-escaped value in terminal stdout after typing `REVEAL`.

Revealed values remain in scrollback/recordings. JSON escaping prevents terminal
control sequences but is not encryption. Use file output for exact multiline data.

```sh
make get VAULT="my-vault" SECRET="api-token"
mkdir -p -m 700 secrets-output
make get VAULT="my-vault" SECRET="api-token" OUTPUT_FILE="secrets-output/api-token"
```

`OUTPUT_FILE` bypasses the output-choice menu. Parent directories are not created
automatically. A failed file write may occur after Azure has returned the value;
the operation report describes overall completion, not a server-side access log.

For a trusted pipe, invoke the Python CLI directly with `--stdout`; Make does not
expose a stdout selector. Terminal stdin is still needed for authentication and
selection, and terminal stdout is refused. All menus/status messages use stderr.
Do not redirect stderr into the secret stream.

```sh
# From keyvault-cli; replace trusted-consumer with your approved program.
.venv/bin/python keyvault_cli.py get --vault "my-vault" --secret "api-token" --stdout | trusted-consumer
```

## Create, import, and update

### `make create` and `make import`

`import` is an alias of `create`, not a batch importer or Azure backup restore.
Both require List/Set permission and refuse names found in the vault's metadata,
including case variants. Confirm the destination by typing `CREATE`.

```sh
make create VAULT="my-vault" SECRET="new-api-token"
make import VAULT="my-vault" SECRET="new-api-token" INPUT_FILE="/path/to/token.txt"
```

Without `INPUT_FILE`, enter the new value twice at hidden prompts. The file must
be owned by the current user and have no group/other permission bits; for example,
apply `chmod 600` to an existing input file. Input must contain 1–25,600 UTF-8
bytes; binary and empty values are rejected. Hidden prompts accept single-line
values; use a protected file for multiline data. The tool does not delete inputs.

### `make update`

Require an existing name, confirm by typing `UPDATE`, then submit a new value.
Azure creates a new secret version; earlier versions are not deleted. Enabled
state, expiry, not-before, content type, and tags are carried over when present
in the metadata response. The previous secret value is not fetched.

```sh
make update VAULT="my-vault" SECRET="api-token"
make update VAULT="my-vault" SECRET="api-token" INPUT_FILE="/path/to/replacement.txt"
```

Existence checks are advisory: Azure `set_secret` is an upsert, not an atomic
create-only/update-only operation. Concurrent writers can change the destination
between the check and the write. Coordinate rotations with other operators.
If the write outcome is reported as `unknown`, Azure may have accepted the
request: check latest metadata before retrying rather than creating extra versions.
Deleted-but-recoverable names can also cause Azure to reject a create; this tool
does not recover, delete, or purge secrets.

## Persistent session and request reports

### `make session` and `make report`

`report` is an alias that starts the same persistent session. It does not read
history from another Make invocation.

```sh
make session VAULT="my-vault"
mkdir -p -m 700 reports
make report VAULT="my-vault" REPORT_FILE="reports/session-001.json"
```

The session menu offers:

- `1`: list secret metadata.
- `2`: retrieve a secret.
- `3`: create/import a secret.
- `4`: update a secret.
- `5`: display the current report.
- `6`: export a new owner-only JSON report to a prompted path.
- `7`: run online Doctor using the session credential. A session-scoped `SECRET`
  also enables Doctor's Get probe; the value is discarded.
- `q`/`quit`: exit. A summary is shown, and `REPORT_FILE` is exported if supplied.

Selectors passed when starting the session remain its defaults. Without fixed
selectors, each operation asks for its resource selection; menu selections are
not remembered as new defaults. `INPUT_FILE` and `OUTPUT_FILE` also remain defaults
for writes/retrievals, so do not reuse a single output path for multiple exports.
At ordinary operation menus, `q` returns to the session menu. Hidden secret-value
prompts treat typed text as data, not commands. Ctrl-C/EOF exits the session.

Reports contain UTC timestamps, operation, selected subscription/vault/secret,
and status (`success`, `failed`, `cancelled`, or an unconfirmed write's `unknown`).
Subscription can be null for direct named-vault access. Reports never include
secret values, tokens, tags, input contents, or raw exceptions.

History exists only in memory until exported; closing a process loses unexported
history. A menu export is a snapshot, not an automatically updated file. An
existing snapshot cannot be overwritten by the final export. Reports are
sensitive resource metadata and are not tamper-proof Azure audit logs. Enable
Azure diagnostic logging separately if authoritative auditing is required.

## Troubleshooting

### `make doctor` and `make Doctor`

Both aliases run local checks without credentials or Azure requests:

```sh
make doctor
make Doctor
```

Checks include Python, Make, virtual environment, Azure dependency imports,
configured identifier format, configured CA-file existence, proxy presence
(not its value), and supplied input/output/report paths. Missing IDs are warnings
because interactive commands can prompt. Doctor works without Azure packages and
suggests `make setup` when they are missing.

Opt into read-only online probes:

```sh
make doctor ONLINE=1 VAULT="my-vault"
make doctor ONLINE=1 VAULT="my-vault" SECRET="api-token"
make doctor ONLINE=1 VAULT="my-vault" \
  SUBSCRIPTION="My Subscription" RESOURCE_GROUP="my-rg"
```

Set `AZURE_TENANT_ID` and `AZURE_CLIENT_ID` first; standalone online Doctor requires
these configured identifiers and does not prompt for them. It uses a hidden
client-secret prompt unless a credential is injected through the environment.

Online checks cover direct DNS/TLS connections to Entra/ARM/the selected vault,
service-principal token acquisition, optional subscription access/membership,
vault List, and an explicitly requested Get with the value discarded. Direct
socket probes do not follow HTTP proxy routing; their warnings do not necessarily
mean the SDK is unable to connect. Doctor never tests Set by creating a secret.

- Authentication rejected: check tenant/client IDs, the credential's **value**
  rather than its secret ID, expiration, application status, and tenant policy.
- ARM access denied: request read permission at the intended discovery scope.
- Vault 403: review data-plane permissions, RBAC propagation, legacy access
  policies, firewall, VPN, and private-endpoint routing. A 403 alone does not
  establish which cause applies.
- DNS/TLS failure: review network/VPN, private DNS, system time, corporate trust
  store, and configured CA bundles. Never disable TLS verification as a fix.
- File-path failure: choose a new destination with an existing writable parent,
  or correct input ownership/permissions.
- Set permission remains `unknown`: ask an administrator for a custom scoped
  List/Get/Set role where appropriate. `Key Vault Secrets User` permits reading,
  not writing. `Key Vault Secrets Officer` is broader than this tool requires.

Doctor prints pass/warn/fail/skip/info/unknown findings. A zero exit status means
no checked item failed, not that skipped/unknown permissions were verified.
It never grants roles, changes firewall rules, installs packages, or modifies
credential configuration.

## Tests, lint, and full workflow dry run

### `make test`

Run all standard-library unittest suites in both directories. Azure clients are
mocked; tests use synthetic values and temporary files. They cover authentication,
selection, confirmed writes, protected files, session reports, errors, Doctor,
and a pseudo-terminal interaction.

```sh
make test
```

### `make lint`

Run Ruff lint and format **checks** for both directories, excluding `.venv`.
This target does not rewrite source files. Use `make setup` if Ruff is missing.

```sh
make lint
```

### Dry run versus simulation

`make -n` prints the shell recipe without running the launcher, Python, setup,
authentication, or any Azure call. It validates Make wiring, not credentials,
RBAC, input files, or the commands hidden behind the Python dispatcher.
Use only non-secret example selectors even during a dry run.

```sh
make -n setup auth login vaults check secrets get create import update session report doctor Doctor test lint help \
  VAULT="example-vault" SECRET="example-token" \
  SUBSCRIPTION="Example Subscription" RESOURCE_GROUP="example-rg" \
  INPUT_FILE="/tmp/example-input.txt" OUTPUT_FILE="/tmp/example-output.txt" \
  REPORT_FILE="/tmp/example-report.json" ONLINE=1
```

The offline `test_workflow.py` additionally checks all target/alias dispatches,
dry-runs every target from both Make entry points, and simulates a same-session
create → retrieve → update → retrieve → report workflow with mocked Azure state.
Run it specifically from `keyvault-cli`:

```sh
.venv/bin/python -m unittest test_workflow -v
```

This verification does not prove access to a live tenant or perform real secret
writes. Run authorized live checks separately when ready; do not remove `-n`
from a multi-target example unless you intend to execute every operation.

## Exit behavior and limitations

Direct Python commands use exit codes `0` success, `1` failure, `2` usage error,
and `130` cancellation. GNU Make usually returns `2` for a failed recipe, so its
exit status does not preserve Python's exact code. A session can exit successfully
even when individual requests failed; inspect its report for per-operation status.

Secrets are not written to a credential cache or log. Python cannot guarantee
memory zeroization, and OS process dumps/debuggers may expose in-memory data.
Retrieval files are plaintext, not encrypted; delete them when no longer needed.
The ignored `secrets-input`, `secrets-output`, and `reports` directories under
`keyvault-cli` help avoid accidental commits, but Git ignores are not access control.
Use the protected paths appropriate to your organization.
