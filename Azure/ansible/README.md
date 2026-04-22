# Azure Ansible Playbook

Runs the Python scripts in `../scripts/` against Azure using a Service Principal.
All secrets live in `group_vars/azure_keys.yml`, encrypted with `ansible-vault`.

## Layout
- `azure_connect.yml` — main playbook
- `inventory.ini` — local inventory (runs against localhost)
- `ansible.cfg` — ansible defaults
- `group_vars/azure_keys.yml` — Service Principal + storage vars (ENCRYPT BEFORE COMMIT)

## 1. Fill in the vault file
Edit `group_vars/azure_keys.yml` and replace the placeholder values:
```yaml
azure_tenant_id: "..."
azure_client_id: "..."
azure_client_secret: "..."
azure_subscription_id: "..."
azure_storage_account: "..."
azure_storage_container: "..."
```

## 2. Encrypt it before pushing to git
```bash
ansible-vault encrypt group_vars/azure_keys.yml
```

To edit it later:
```bash
ansible-vault edit group_vars/azure_keys.yml
```

To decrypt temporarily (do NOT commit the decrypted version):
```bash
ansible-vault decrypt group_vars/azure_keys.yml
```

## 3. Run the playbook
Prompt for the vault password:
```bash
ansible-playbook azure_connect.yml --ask-vault-pass
```

Or use a password file (add it to `.gitignore`):
```bash
ansible-playbook azure_connect.yml --vault-password-file ~/.ansible/vault_pass.txt
```

## Notes
- The playbook installs the required Python packages (`azure-identity`,
  `azure-mgmt-resource`, `azure-storage-blob`, `python-dotenv`) via `pip3`.
- Vault variables are injected into the scripts as environment variables,
  so the scripts do not need a `.env` file when invoked from Ansible.
- The Service Principal needs a data-plane RBAC role on the storage account
  (e.g. **Storage Blob Data Reader** or **Storage Blob Data Contributor**)
  to read/write blobs.
