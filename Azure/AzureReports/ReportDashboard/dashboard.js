// Global data storage
const dashboardData = {
    reports: [],
    parsedData: {},
    charts: {}
};

// Report type mappings
const reportTypes = {
    'MFAStatus': { category: 'azure-iam', name: 'MFA Status Report' },
    'GuestUserReport': { category: 'azure-iam', name: 'Guest User Report' },
    'PasswordPolicyReport': { category: 'azure-iam', name: 'Password Policy Report' },
    'ConditionalAccessReport': { category: 'azure-iam', name: 'Conditional Access Report' },
    'VMTLSConfiguration': { category: 'azure-data', name: 'VM TLS Configuration' },
    'VMEncryptionStatus': { category: 'azure-data', name: 'VM Encryption Status' },
    'SecurityComplianceReport': { category: 'azure-data', name: 'Security Compliance Report' },
    'StorageSecurityReport': { category: 'azure-infra', name: 'Storage Security Report' },
    'PublicBlobReport': { category: 'azure-infra', name: 'Public Blob Report' },
    'KeyVaultSecurityReport': { category: 'azure-infra', name: 'Key Vault Security' },
    'CertificateExpirationReport': { category: 'azure-infra', name: 'Certificate Expiration' },
    'NSGAnalysisReport': { category: 'azure-infra', name: 'NSG Analysis' },
    'FirewallRulesReport': { category: 'azure-infra', name: 'Firewall Rules' },
    'ResourceTagComplianceReport': { category: 'azure-infra', name: 'Tag Compliance' },
    'LicenseUsageReport': { category: 'o365-licensing', name: 'License Usage' },
    'CostOptimizationReport': { category: 'o365-licensing', name: 'Cost Optimization' },
    'UnassignedLicensesReport': { category: 'o365-licensing', name: 'Unassigned Licenses' },
    'InactiveAccountReport': { category: 'o365-users', name: 'Inactive Accounts' },
    'LicensedInactiveAccountReport': { category: 'o365-users', name: 'Licensed Inactive Accounts' },
    'UserSecurityRiskReport': { category: 'o365-users', name: 'User Security Risk' },
    'MailboxForwardingRulesReport': { category: 'o365-email', name: 'Mailbox Forwarding Rules' },
    'ExternalForwardingReport': { category: 'o365-email', name: 'External Forwarding' },
    'ExchangeSecurityReport': { category: 'o365-email', name: 'Exchange Security' },
    'TeamsExternalAccessReport': { category: 'o365-teams', name: 'Teams External Access' },
    'TeamsExternalUsersReport': { category: 'o365-teams', name: 'Teams External Users' },
    'TeamsSecurityPostureReport': { category: 'o365-teams', name: 'Teams Security Posture' },
    'TeamsChannelMembershipReport': { category: 'o365-teams', name: 'Teams Channel Membership' },
    'SharePointSharingReport': { category: 'o365-sharepoint', name: 'SharePoint Sharing' },
    'SharePointStorageReport': { category: 'o365-sharepoint', name: 'SharePoint Storage' },
    'OneDriveSecurityReport': { category: 'o365-sharepoint', name: 'OneDrive Security' },
    'DLPPolicyGuidance': { category: 'o365-sharepoint', name: 'DLP Policy Guidance' },
    'ExternalSharingReport': { category: 'o365-sharepoint', name: 'External Sharing' },
    'OneDriveSharingLinksReport': { category: 'o365-sharepoint', name: 'OneDrive Sharing Links' }
};

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    setupFileUpload();
    loadStoredData();
    updateDashboard();
});

// Tab switching
function switchTab(tabName) {
    // Update tabs
    document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(tabName).classList.add('active');
    
    // Load category data if not overview or upload
    if (tabName !== 'overview' && tabName !== 'upload') {
        loadCategoryData(tabName);
    }
}

// File upload setup
function setupFileUpload() {
    const uploadArea = document.getElementById('uploadArea');
    const fileInput = document.getElementById('fileInput');
    
    // Drag and drop
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });
    
    // File input change
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });
}

// Handle file uploads
function handleFiles(files) {
    Array.from(files).forEach(file => {
        if (file.name.endsWith('.csv')) {
            Papa.parse(file, {
                header: true,
                skipEmptyLines: true,
                complete: (results) => {
                    processReport(file.name, results.data);
                },
                error: (error) => {
                    console.error('Error parsing CSV:', error);
                    alert(`Error parsing ${file.name}: ${error.message}`);
                }
            });
        }
    });
}

// Process uploaded report
function processReport(filename, data) {
    // Detect report type from filename
    let reportType = null;
    for (const [key, value] of Object.entries(reportTypes)) {
        if (filename.includes(key)) {
            reportType = key;
            break;
        }
    }
    
    if (!reportType) {
        console.warn(`Unknown report type: ${filename}`);
        return;
    }
    
    // Store report
    const report = {
        id: Date.now() + Math.random(),
        filename: filename,
        type: reportType,
        category: reportTypes[reportType].category,
        name: reportTypes[reportType].name,
        data: data,
        timestamp: new Date().toISOString()
    };
    
    dashboardData.reports.push(report);
    dashboardData.parsedData[reportType] = data;
    
    // Save to localStorage
    saveData();
    
    // Update UI
    updateFilesList();
    updateDashboard();
    
    // Show success message
    console.log(`Loaded: ${filename} (${data.length} rows)`);
}

// Update files list
function updateFilesList() {
    const container = document.getElementById('loadedFiles');
    container.innerHTML = dashboardData.reports.map(report => `
        <span class="file-badge">
            <i class="fas fa-file-csv"></i> ${report.filename}
            <button onclick="removeReport('${report.id}')">
                <i class="fas fa-times"></i>
            </button>
        </span>
    `).join('');
}

// Remove report
function removeReport(id) {
    dashboardData.reports = dashboardData.reports.filter(r => r.id !== parseFloat(id));
    saveData();
    updateFilesList();
    updateDashboard();
}

// Clear all data
function clearAllData() {
    if (confirm('Are you sure you want to clear all uploaded reports?')) {
        dashboardData.reports = [];
        dashboardData.parsedData = {};
        localStorage.removeItem('dashboardReports');
        updateFilesList();
        updateDashboard();
    }
}

// Save data to localStorage
function saveData() {
    try {
        localStorage.setItem('dashboardReports', JSON.stringify(dashboardData.reports));
    } catch (e) {
        console.error('Error saving data:', e);
    }
}

// Load stored data
function loadStoredData() {
    try {
        const stored = localStorage.getItem('dashboardReports');
        if (stored) {
            dashboardData.reports = JSON.parse(stored);
            dashboardData.reports.forEach(report => {
                dashboardData.parsedData[report.type] = report.data;
            });
            updateFilesList();
        }
    } catch (e) {
        console.error('Error loading data:', e);
    }
}

// Update dashboard overview
function updateDashboard() {
    updateStats();
    updateCharts();
}

// Update statistics
function updateStats() {
    const totalReports = dashboardData.reports.length;
    document.getElementById('total-reports').textContent = totalReports;
    
    if (totalReports === 0) {
        document.getElementById('critical-issues').textContent = '0';
        document.getElementById('warning-count').textContent = '0';
        document.getElementById('avg-score').textContent = '-';
        return;
    }
    
    let criticalCount = 0;
    let warningCount = 0;
    let scores = [];
    
    // Analyze all reports
    dashboardData.reports.forEach(report => {
        const data = report.data;
        
        data.forEach(row => {
            // Check for risk levels
            const riskLevel = (row.RiskLevel || row.Risk || row.Status || '').toLowerCase();
            if (riskLevel.includes('critical') || riskLevel.includes('high')) {
                criticalCount++;
            } else if (riskLevel.includes('medium') || riskLevel.includes('warning')) {
                warningCount++;
            }
            
            // Extract scores
            const score = parseFloat(row.SecurityScore || row.Score || row.ComplianceScore);
            if (!isNaN(score)) {
                scores.push(score);
            }
        });
    });
    
    document.getElementById('critical-issues').textContent = criticalCount;
    document.getElementById('warning-count').textContent = warningCount;
    
    if (scores.length > 0) {
        const avgScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
        document.getElementById('avg-score').textContent = avgScore;
    } else {
        document.getElementById('avg-score').textContent = '-';
    }
}

// Update charts
function updateCharts() {
    updateCategoryChart();
    updateRiskChart();
    updateScoreChart();
}

// Category distribution chart
function updateCategoryChart() {
    const ctx = document.getElementById('categoryChart');
    if (!ctx) return;
    
    if (dashboardData.charts.category) {
        dashboardData.charts.category.destroy();
    }
    
    // Count reports by category
    const categories = {};
    dashboardData.reports.forEach(report => {
        const cat = report.category.replace('azure-', 'Azure ').replace('o365-', 'O365 ')
            .split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
        categories[cat] = (categories[cat] || 0) + 1;
    });
    
    dashboardData.charts.category = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(categories),
            datasets: [{
                data: Object.values(categories),
                backgroundColor: [
                    '#0078d4', '#107c10', '#ff8c00', '#d13438',
                    '#5c2d91', '#008272', '#ca5010', '#004e8c'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right'
                }
            }
        }
    });
}

// Risk distribution chart
function updateRiskChart() {
    const ctx = document.getElementById('riskChart');
    if (!ctx) return;
    
    if (dashboardData.charts.risk) {
        dashboardData.charts.risk.destroy();
    }
    
    const risks = { Critical: 0, High: 0, Medium: 0, Low: 0, None: 0 };
    
    dashboardData.reports.forEach(report => {
        report.data.forEach(row => {
            const risk = (row.RiskLevel || row.Risk || row.Status || 'None').toLowerCase();
            if (risk.includes('critical')) risks.Critical++;
            else if (risk.includes('high')) risks.High++;
            else if (risk.includes('medium')) risks.Medium++;
            else if (risk.includes('low')) risks.Low++;
            else risks.None++;
        });
    });
    
    dashboardData.charts.risk = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(risks),
            datasets: [{
                label: 'Risk Items',
                data: Object.values(risks),
                backgroundColor: ['#d13438', '#ff8c00', '#ffaa44', '#107c10', '#0078d4']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Security scores chart
function updateScoreChart() {
    const ctx = document.getElementById('scoreChart');
    if (!ctx) return;
    
    if (dashboardData.charts.score) {
        dashboardData.charts.score.destroy();
    }
    
    const categoryScores = {};
    
    dashboardData.reports.forEach(report => {
        const cat = report.category;
        if (!categoryScores[cat]) {
            categoryScores[cat] = { total: 0, count: 0 };
        }
        
        report.data.forEach(row => {
            const score = parseFloat(row.SecurityScore || row.Score || row.ComplianceScore);
            if (!isNaN(score)) {
                categoryScores[cat].total += score;
                categoryScores[cat].count++;
            }
        });
    });
    
    const labels = [];
    const scores = [];
    
    Object.keys(categoryScores).forEach(cat => {
        if (categoryScores[cat].count > 0) {
            const catName = cat.replace('azure-', 'Azure ').replace('o365-', 'O365 ')
                .split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
            labels.push(catName);
            scores.push(Math.round(categoryScores[cat].total / categoryScores[cat].count));
        }
    });
    
    dashboardData.charts.score = new Chart(ctx, {
        type: 'horizontalBar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Average Score',
                data: scores,
                backgroundColor: '#0078d4'
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    max: 100
                }
            }
        }
    });
}

// Load category-specific data
function loadCategoryData(category) {
    const contentDiv = document.getElementById(`${category}-content`);
    if (!contentDiv) return;
    
    // Get reports for this category
    const categoryReports = dashboardData.reports.filter(r => r.category === category);
    
    if (categoryReports.length === 0) {
        contentDiv.innerHTML = `
            <div class="empty-state">
                <div style="font-size: 3rem; opacity: 0.3;"><i class="fas fa-inbox"></i></div>
                <h3>No Reports Loaded</h3>
                <p>Upload CSV reports to see data for this category</p>
            </div>
        `;
        return;
    }
    
    let html = `<div class="card-header"><h2 class="card-title">${getCategoryTitle(category)}</h2></div>`;
    
    categoryReports.forEach(report => {
        html += `
            <div style="margin-bottom: 2rem;">
                <h3 style="color: var(--primary); margin-bottom: 1rem;">
                    <i class="fas fa-file-csv"></i> ${report.name}
                </h3>
                <p style="color: var(--text-light); margin-bottom: 1rem;">
                    <small>${report.filename} - ${report.data.length} records</small>
                </p>
                ${createFilters(report.data)}
                ${createDataTable(report.data, report.type)}
            </div>
        `;
    });
    
    contentDiv.innerHTML = html;
    
    // Attach filter listeners
    attachFilterListeners();
}

// Get category title
function getCategoryTitle(category) {
    const titles = {
        'azure-iam': 'Azure Identity & Access Management',
        'azure-data': 'Azure Data Protection',
        'azure-infra': 'Azure Infrastructure Security',
        'o365-licensing': 'Office 365 Licensing',
        'o365-users': 'Office 365 User Security',
        'o365-email': 'Office 365 Email Security',
        'o365-teams': 'Microsoft Teams Security',
        'o365-sharepoint': 'SharePoint & OneDrive Security'
    };
    return titles[category] || category;
}

// Create filters
function createFilters(data) {
    if (data.length === 0) return '';
    
    const columns = Object.keys(data[0]);
    const filterableColumns = columns.filter(col => 
        col.toLowerCase().includes('risk') || 
        col.toLowerCase().includes('status') ||
        col.toLowerCase().includes('enabled') ||
        col.toLowerCase().includes('level')
    );
    
    if (filterableColumns.length === 0) return '';
    
    return `
        <div class="filters">
            <div class="filter-group">
                <label>Search</label>
                <input type="text" class="filter-search" placeholder="Search...">
            </div>
            ${filterableColumns.slice(0, 2).map(col => {
                const uniqueValues = [...new Set(data.map(row => row[col]))].filter(v => v);
                return `
                    <div class="filter-group">
                        <label>${col}</label>
                        <select class="filter-select" data-column="${col}">
                            <option value="">All</option>
                            ${uniqueValues.map(val => `<option value="${val}">${val}</option>`).join('')}
                        </select>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

// Create data table
function createDataTable(data, reportType) {
    if (data.length === 0) return '<p>No data available</p>';
    
    const columns = Object.keys(data[0]);
    const displayColumns = columns.slice(0, 8); // Limit displayed columns
    
    return `
        <div class="table-container">
            <table class="data-table">
                <thead>
                    <tr>
                        ${displayColumns.map(col => `<th>${col}</th>`).join('')}
                    </tr>
                </thead>
                <tbody>
                    ${data.map((row, idx) => `
                        <tr data-row-index="${idx}">
                            ${displayColumns.map(col => {
                                let value = row[col] || '-';
                                
                                // Apply badges for status/risk columns
                                if (col.toLowerCase().includes('risk') || col.toLowerCase().includes('status')) {
                                    const lower = value.toLowerCase();
                                    let badgeClass = 'badge-info';
                                    if (lower.includes('critical') || lower.includes('high')) badgeClass = 'badge-danger';
                                    else if (lower.includes('medium') || lower.includes('warning')) badgeClass = 'badge-warning';
                                    else if (lower.includes('low') || lower.includes('success')) badgeClass = 'badge-success';
                                    
                                    value = `<span class="badge ${badgeClass}">${value}</span>`;
                                }
                                
                                // Format scores
                                if (col.toLowerCase().includes('score')) {
                                    const score = parseFloat(value);
                                    if (!isNaN(score)) {
                                        let color = 'var(--success)';
                                        if (score < 50) color = 'var(--danger)';
                                        else if (score < 75) color = 'var(--warning)';
                                        value = `<strong style="color: ${color}">${score}</strong>`;
                                    }
                                }
                                
                                return `<td>${value}</td>`;
                            }).join('')}
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Attach filter listeners
function attachFilterListeners() {
    // Search filter
    document.querySelectorAll('.filter-search').forEach(input => {
        input.addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();
            const table = e.target.closest('.card').querySelector('table');
            
            table.querySelectorAll('tbody tr').forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });
    });
    
    // Select filters
    document.querySelectorAll('.filter-select').forEach(select => {
        select.addEventListener('change', (e) => {
            const column = e.target.dataset.column;
            const value = e.target.value;
            const table = e.target.closest('.card').querySelector('table');
            const columnIndex = Array.from(table.querySelectorAll('thead th'))
                .findIndex(th => th.textContent === column);
            
            if (columnIndex === -1) return;
            
            table.querySelectorAll('tbody tr').forEach(row => {
                const cell = row.querySelectorAll('td')[columnIndex];
                if (!cell) return;
                
                const cellText = cell.textContent.trim();
                row.style.display = (value === '' || cellText === value) ? '' : 'none';
            });
        });
    });
}
