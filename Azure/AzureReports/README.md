# Azure & Office 365 Security Audit Dashboard

A comprehensive, interactive dashboard providing ready-to-use security auditing scripts for Azure and Office 365 in **Bash**, **PowerShell**, and **Python**.

## 🎯 Overview

This dashboard serves as your **one-stop shop** for security auditing and compliance reporting across Azure and Office 365 environments. Select any security check, choose your preferred language, and get production-ready scripts instantly.

## ✨ Features

- **🔐 Azure Security Auditing**
  - Identity & Access Management (IAM)
  - Data Protection & Encryption
  - Infrastructure Security
  - Resource Compliance

- **☁️ Office 365 Security Auditing**
  - License Management & Optimization
  - User Account Security
  - Email Security & Forwarding Detection
  - Microsoft Teams Security
  - SharePoint & OneDrive Security

- **💻 Multi-Language Support**
  - Bash scripts for Linux/macOS
  - PowerShell scripts for Windows/cross-platform
  - Python scripts for maximum flexibility

- **📋 Interactive Dashboard**
  - Clean, modern UI
  - Script search functionality
  - One-click copy & download
  - Organized by security category

## 🚀 Quick Start

### Prerequisites

#### For All Scripts
- Active Azure subscription
- Appropriate permissions for the resources you want to audit

#### Language-Specific Requirements

**PowerShell Scripts:**
- PowerShell 7+ recommended
- Azure PowerShell modules
- Microsoft Graph PowerShell SDK
- Exchange Online Management module (for email scripts)

### Installation

1. **Clone or download this repository**

2. **Open the dashboard**
   ```bash
   # Simply open the dashboard.html file in your browser
   open dashboard.html  # macOS
   xdg-open dashboard.html  # Linux
   start dashboard.html  # Windows
   ```

3. **Install required tools** (based on your preferred language)

#### PowerShell Setup
```powershell
# Install Azure PowerShell
Install-Module -Name Az -Repository PSGallery -Force

# Install Microsoft Graph PowerShell
Install-Module -Name Microsoft.Graph -Repository PSGallery -Force

# Install Exchange Online Management
Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Force

# Connect to Azure
Connect-AzAccount

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All"
```

## 📖 Usage

1. **Launch the Dashboard**
   - Open `dashboard.html` in your web browser

2. **Select Your Language**
   - Choose between Bash, PowerShell, or Python at the top

3. **Browse Security Categories**
   - Click on any category in the left sidebar to expand
   - Select a specific audit script

4. **Use the Script**
   - **Copy**: Click the "Copy" button to copy to clipboard
   - **Download**: Click "Download" to save as a file
   - **Run**: Execute the script in your terminal/shell

5. **Search Functionality**
   - Use the search bar to quickly find specific audits

## 🔒 Security Best Practices

### Authentication

1. **Use Service Principals for Automation**
   - Run the "Configuration & Credential Setup" script
   - Store credentials securely using system keyring

2. **Principle of Least Privilege**
   - Grant only required permissions
   - Use read-only roles when possible

3. **Credential Management**
   - Never hardcode credentials
   - Use Azure Key Vault for production
   - Rotate secrets regularly

### Script Execution

1. **Review Before Running**
   - Always review scripts before execution
   - Understand what data will be collected

2. **Test in Non-Production**
   - Test scripts in dev/test environments first
   - Verify permissions and access

3. **Audit Logs**
   - Scripts generate timestamped reports
   - Store reports securely
   - Review findings promptly

## 📊 Available Audit Scripts

### Azure Security

#### Identity & Access Management
- **MFA Status Analysis**: Check MFA enrollment across all users
- **Guest User Review**: Audit external user access
- **Password Policy Assessment**: Review password policies
- **Conditional Access Evaluation**: Analyze CA policies

#### Data Protection
- **VM TLS Configuration**: Verify TLS settings on VMs
- **Disk Encryption Status**: Check VM disk encryption
- **Security Compliance**: Overall security posture

#### Infrastructure Security
- **Storage Account Security**: Audit storage configurations
- **Public Blob Detection**: Find publicly accessible blobs
- **Key Vault Security**: Review Key Vault settings
- **Certificate Expiration**: Monitor certificate lifecycle
- **NSG Analysis**: Review network security groups
- **Firewall Rules**: Detect dangerous firewall rules
- **Resource Tag Compliance**: Audit resource tagging

### Office 365 Security

#### License Management
- **License Usage Analysis**: Detailed license consumption
- **Cost Optimization**: Identify unused licenses
- **Unassigned Licenses**: Find available licenses

#### User Security
- **Inactive Accounts**: Detect 90+ day inactive users
- **Licensed Inactive**: Find licensed but inactive accounts

#### Email Security
- **Mailbox Forwarding**: Detect forwarding rules
- **External Forwarding**: Identify external email forwards

#### Teams Security
- **External Access Review**: Check Teams external access
- **Teams with Guests**: List Teams with guest users
- **Channel Membership**: Report Teams channel members

#### SharePoint/OneDrive
- **Sharing Settings**: Audit sharing configurations
- **Storage Usage**: Monitor storage consumption
- **OneDrive Sharing Links**: Detect external sharing

## 🛠️ Configuration Management

Use the **Configuration & Credential Setup** script to:

1. **Create Service Principal**
   - Automates SP creation
   - Assigns appropriate roles

2. **Store Credentials Securely**
   - Uses OS keyring/credential manager
   - Supports macOS Keychain, Windows Credential Manager

3. **Configure Export Paths**
   - Set default report locations
   - Organize audit results

4. **Enable Auto-Connect**
   - Streamline authentication
   - Reduce manual login steps

## 📁 Report Outputs

All scripts generate CSV reports with timestamps:

```
mfa_status_report_20240123_143022.csv
guest_users_report_20240123_143045.csv
storage_security_report_20240123_143110.csv
...
```

Reports include:
- Detailed findings
- Timestamps
- Resource identifiers
- Security status
- Recommendations

## 🔍 Troubleshooting

### Common Issues

**Permission Errors**
```
Solution: Ensure you have the required roles and scopes
- Azure: Contributor, Reader, or specific resource access
- Microsoft Graph: Appropriate API permissions
```

**Authentication Failures**
```
Solution: Re-authenticate or check service principal
- Bash/Python: Run 'az login'
- PowerShell: Run 'Connect-AzAccount' and 'Connect-MgGraph'
```

**Module Not Found (PowerShell)**
```
Solution: Install required modules
Install-Module -Name Az -Force
Install-Module -Name Microsoft.Graph -Force
```

**Import Errors (Python)**
```
Solution: Install required packages
pip install azure-identity azure-mgmt-storage msgraph-sdk
```

## 🤝 Contributing

Feel free to extend this dashboard with additional scripts:

1. Add script definitions to `scripts.js`
2. Include all three language implementations
3. Update the sidebar navigation
4. Test thoroughly before committing

## 📝 Script Template

When adding new scripts, use this structure:

```javascript
'script-id': {
    title: '🔒 Script Title',
    description: 'Brief description of what the script does',
    requirements: ['Requirement 1', 'Requirement 2'],
    bash: `#!/bin/bash
    # Your bash script here
    `,
    powershell: `# Your PowerShell script here
    `,
    python: `#!/usr/bin/env python3
    # Your Python script here
    `
}
```

## 🔐 Required Permissions

### Azure Permissions
- **Reader**: Minimum for most read operations
- **Security Reader**: For security-related queries
- **Storage Account Contributor**: For storage audits

### Microsoft Graph Permissions
- `User.Read.All`: Read user information
- `Directory.Read.All`: Read directory data
- `AuditLog.Read.All`: Read audit logs
- `UserAuthenticationMethod.Read.All`: Read MFA status
- `Organization.Read.All`: Read license information

### Exchange Online Permissions
- **View-Only Recipients**: For mailbox audits
- **Compliance Management**: For forwarding detection

## 📚 Additional Resources

- [Azure CLI Documentation](https://docs.microsoft.com/cli/azure/)
- [Azure PowerShell Documentation](https://docs.microsoft.com/powershell/azure/)
- [Microsoft Graph Documentation](https://docs.microsoft.com/graph/)
- [Azure Security Best Practices](https://docs.microsoft.com/azure/security/)
- [Microsoft 365 Security](https://docs.microsoft.com/microsoft-365/security/)

## 🎓 Learning Path

1. **Start with basic audits**: MFA Status, Guest Users
2. **Progress to infrastructure**: Storage, NSG, Key Vault
3. **Explore Office 365**: Licenses, Mailboxes, Teams
4. **Automate regular checks**: Use scheduled tasks/cron
5. **Build dashboards**: Visualize audit results

## ⚠️ Disclaimer

These scripts are provided as-is for auditing and compliance purposes. Always:
- Test in non-production environments first
- Review scripts before execution
- Ensure you have proper authorization
- Follow your organization's security policies
- Maintain audit logs of script execution

## 📄 License

See LICENSE.txt in the repository root.

## 🆘 Support

For issues or questions:
1. Review the script requirements
2. Check the troubleshooting section
3. Verify your permissions
4. Review Azure/Microsoft 365 documentation

---

**Happy Auditing! 🔒**

Remember: Security is not a one-time effort but an ongoing process. Regular audits help maintain a strong security posture.
