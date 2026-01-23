// Global State
let rawData = [];
let filteredData = [];
let currentPage = 1;
const itemsPerPage = 50;
let charts = {};

// Policy name mapping for common Azure policy IDs
const policyNameMapping = {
    // Add common policy ID to name mappings
    'audit-vm-managed-disks': 'Audit VMs without Managed Disks',
    'allowed-locations': 'Allowed Locations',
    'allowed-resource-types': 'Allowed Resource Types',
    'deny-ip-forwarding': 'Deny IP Forwarding',
    'enforce-tag-and-value': 'Enforce Tag and Value',
    'require-sql-db-encryption': 'Require SQL DB Encryption',
    // Add more mappings as needed
};

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    setupFileUpload();
    setupFilters();
    setupSearch();
    setupExport();
});

// File Upload Setup
function setupFileUpload() {
    const fileInput = document.getElementById('fileInput');
    const uploadArea = document.getElementById('uploadArea');

    fileInput.addEventListener('change', handleFileSelect);

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
        const file = e.dataTransfer.files[0];
        if (file && file.name.endsWith('.csv')) {
            processFile(file);
        }
    });
}

// Handle File Selection
function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        processFile(file);
    }
}

// Process CSV File
function processFile(file) {
    const fileInfo = document.getElementById('fileInfo');
    fileInfo.innerHTML = `<p>Loading ${file.name}... <span class="loading"></span></p>`;
    fileInfo.style.display = 'block';

    Papa.parse(file, {
        header: true,
        skipEmptyLines: true,
        complete: (results) => {
            rawData = normalizeData(results.data);
            filteredData = [...rawData];
            
            fileInfo.innerHTML = `
                <p><strong>✓ File loaded successfully:</strong> ${file.name}</p>
                <p><strong>Total records:</strong> ${rawData.length.toLocaleString()}</p>
            `;
            
            initializeDashboard();
        },
        error: (error) => {
            fileInfo.innerHTML = `<p style="color: var(--non-compliant-red);">Error loading file: ${error.message}</p>`;
        }
    });
}

// Normalize data to handle different CSV formats and column names
function normalizeData(data) {
    return data.map(row => ({
        resourceName: row.resourceName || row.ResourceName || row.resource_name || '',
        resourceLocation: row.resourceLocation || row.ResourceLocation || row.resource_location || '',
        resourceType: row.resourcetype || row.resourceType || row.ResourceType || row.resource_type || '',
        complianceState: row.compliancestate || row.complianceState || row.ComplianceState || row.compliance_state || '',
        policyDefinitionName: row.policydefinitionname || row.policyDefinitionName || row.PolicyDefinitionName || row.policy_definition_name || '',
        subscriptionName: row.subscriptionname || row.subscriptionName || row.SubscriptionName || row.subscription_name || '',
        initiativeDisplayName: row.initiativedisplayname || row.initiativeDisplayName || row.InitiativeDisplayName || row.initiative_display_name || '',
        resourceGroup: row.resourcegroup || row.resourceGroup || row.ResourceGroup || row.resource_group || ''
    }));
}

// Initialize Dashboard
function initializeDashboard() {
    document.getElementById('dashboardContent').style.display = 'block';
    
    updateSummaryCards();
    populateFilters();
    renderCharts();
    renderTable();
}

// Update Summary Cards
function updateSummaryCards() {
    const compliant = filteredData.filter(r => 
        r.complianceState.toLowerCase() === 'compliant'
    ).length;
    
    const nonCompliant = filteredData.filter(r => 
        r.complianceState.toLowerCase() === 'noncompliant' || 
        r.complianceState.toLowerCase() === 'non-compliant'
    ).length;
    
    const total = filteredData.length;
    const uniqueResources = new Set(filteredData.map(r => r.resourceName)).size;
    const uniquePolicies = new Set(filteredData.map(r => r.policyDefinitionName)).size;
    
    const compliantPercentage = total > 0 ? ((compliant / total) * 100).toFixed(1) : 0;
    const nonCompliantPercentage = total > 0 ? ((nonCompliant / total) * 100).toFixed(1) : 0;
    
    document.getElementById('compliantCount').textContent = compliant.toLocaleString();
    document.getElementById('compliantPercentage').textContent = `${compliantPercentage}%`;
    document.getElementById('nonCompliantCount').textContent = nonCompliant.toLocaleString();
    document.getElementById('nonCompliantPercentage').textContent = `${nonCompliantPercentage}%`;
    document.getElementById('totalResources').textContent = uniqueResources.toLocaleString();
    document.getElementById('totalPolicies').textContent = uniquePolicies.toLocaleString();
}

// Populate Filter Dropdowns
function populateFilters() {
    populateFilter('resourceTypeFilter', 'resourceType');
    populateFilter('subscriptionFilter', 'subscriptionName');
    populateFilter('resourceGroupFilter', 'resourceGroup');
    populatePolicyFilter();
}

function populateFilter(elementId, field) {
    const select = document.getElementById(elementId);
    const values = [...new Set(rawData.map(item => item[field]).filter(v => v))].sort();
    
    // Clear existing options except the first one
    select.innerHTML = '<option value="all">' + select.options[0].text + '</option>';
    
    values.forEach(value => {
        const option = document.createElement('option');
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
    });
}

function populatePolicyFilter() {
    const select = document.getElementById('policyFilter');
    const policies = [...new Set(rawData.map(item => item.policyDefinitionName).filter(v => v))].sort();
    
    select.innerHTML = '<option value="all">All Policies</option>';
    
    policies.forEach(policy => {
        const option = document.createElement('option');
        option.value = policy;
        option.textContent = getPolicyDisplayName(policy);
        select.appendChild(option);
    });
}

// Get friendly policy name
function getPolicyDisplayName(policyId) {
    // Try to extract readable name from policy ID
    if (!policyId) return 'Unknown Policy';
    
    // Check if we have a mapping
    if (policyNameMapping[policyId]) {
        return policyNameMapping[policyId];
    }
    
    // Try to extract from GUID format
    const match = policyId.match(/\/([^\/]+)$/);
    if (match) {
        const name = match[1];
        // Convert kebab-case or snake_case to Title Case
        return name
            .replace(/[-_]/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }
    
    return policyId;
}

// Setup Filters
function setupFilters() {
    const filters = [
        'complianceFilter',
        'resourceTypeFilter',
        'subscriptionFilter',
        'resourceGroupFilter',
        'policyFilter'
    ];
    
    filters.forEach(id => {
        document.getElementById(id)?.addEventListener('change', applyFilters);
    });
    
    document.getElementById('resetFilters')?.addEventListener('click', resetFilters);
}

// Apply Filters
function applyFilters() {
    const complianceFilter = document.getElementById('complianceFilter').value;
    const resourceTypeFilter = document.getElementById('resourceTypeFilter').value;
    const subscriptionFilter = document.getElementById('subscriptionFilter').value;
    const resourceGroupFilter = document.getElementById('resourceGroupFilter').value;
    const policyFilter = document.getElementById('policyFilter').value;
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    
    filteredData = rawData.filter(item => {
        // Compliance filter
        if (complianceFilter !== 'all') {
            const itemCompliance = item.complianceState.toLowerCase();
            const filterCompliance = complianceFilter.toLowerCase();
            if (filterCompliance === 'noncompliant' && 
                itemCompliance !== 'noncompliant' && 
                itemCompliance !== 'non-compliant') {
                return false;
            } else if (filterCompliance === 'compliant' && itemCompliance !== 'compliant') {
                return false;
            }
        }
        
        // Resource type filter
        if (resourceTypeFilter !== 'all' && item.resourceType !== resourceTypeFilter) {
            return false;
        }
        
        // Subscription filter
        if (subscriptionFilter !== 'all' && item.subscriptionName !== subscriptionFilter) {
            return false;
        }
        
        // Resource group filter
        if (resourceGroupFilter !== 'all' && item.resourceGroup !== resourceGroupFilter) {
            return false;
        }
        
        // Policy filter
        if (policyFilter !== 'all' && item.policyDefinitionName !== policyFilter) {
            return false;
        }
        
        // Search filter
        if (searchTerm) {
            const searchableText = Object.values(item).join(' ').toLowerCase();
            if (!searchableText.includes(searchTerm)) {
                return false;
            }
        }
        
        return true;
    });
    
    currentPage = 1;
    updateSummaryCards();
    renderCharts();
    renderTable();
}

// Reset Filters
function resetFilters() {
    document.getElementById('complianceFilter').value = 'all';
    document.getElementById('resourceTypeFilter').value = 'all';
    document.getElementById('subscriptionFilter').value = 'all';
    document.getElementById('resourceGroupFilter').value = 'all';
    document.getElementById('policyFilter').value = 'all';
    document.getElementById('searchInput').value = '';
    applyFilters();
}

// Setup Search
function setupSearch() {
    const searchInput = document.getElementById('searchInput');
    let debounceTimer;
    
    searchInput?.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(applyFilters, 300);
    });
}

// Render Charts
function renderCharts() {
    renderComplianceChart();
    renderTopPoliciesChart();
    renderResourceTypeChart();
    renderSubscriptionChart();
    renderTrendChart();
}

// Compliance Overview Chart (Doughnut)
function renderComplianceChart() {
    const ctx = document.getElementById('complianceChart');
    
    const compliant = filteredData.filter(r => 
        r.complianceState.toLowerCase() === 'compliant'
    ).length;
    
    const nonCompliant = filteredData.filter(r => 
        r.complianceState.toLowerCase() === 'noncompliant' || 
        r.complianceState.toLowerCase() === 'non-compliant'
    ).length;
    
    if (charts.compliance) {
        charts.compliance.destroy();
    }
    
    charts.compliance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Compliant', 'Non-Compliant'],
            datasets: [{
                data: [compliant, nonCompliant],
                backgroundColor: ['#10b981', '#ef4444'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        font: { size: 14 }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const total = compliant + nonCompliant;
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return `${context.label}: ${context.parsed.toLocaleString()} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Top 10 Non-Compliant Policies Chart (Horizontal Bar)
function renderTopPoliciesChart() {
    const ctx = document.getElementById('topPoliciesChart');
    
    const nonCompliantData = filteredData.filter(r => 
        r.complianceState.toLowerCase() === 'noncompliant' || 
        r.complianceState.toLowerCase() === 'non-compliant'
    );
    
    const policyCounts = {};
    nonCompliantData.forEach(item => {
        const policy = item.policyDefinitionName || 'Unknown';
        policyCounts[policy] = (policyCounts[policy] || 0) + 1;
    });
    
    const sortedPolicies = Object.entries(policyCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    if (charts.topPolicies) {
        charts.topPolicies.destroy();
    }
    
    charts.topPolicies = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedPolicies.map(([policy]) => 
                truncateText(getPolicyDisplayName(policy), 40)
            ),
            datasets: [{
                label: 'Non-Compliant Resources',
                data: sortedPolicies.map(([, count]) => count),
                backgroundColor: '#ef4444',
                borderRadius: 6
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return getPolicyDisplayName(sortedPolicies[context[0].dataIndex][0]);
                        }
                    }
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { precision: 0 }
                }
            }
        }
    });
}

// Compliance by Resource Type Chart (Stacked Bar)
function renderResourceTypeChart() {
    const ctx = document.getElementById('resourceTypeChart');
    
    const resourceTypes = [...new Set(filteredData.map(r => r.resourceType))].filter(v => v);
    
    const compliantCounts = {};
    const nonCompliantCounts = {};
    
    resourceTypes.forEach(type => {
        const typeData = filteredData.filter(r => r.resourceType === type);
        compliantCounts[type] = typeData.filter(r => 
            r.complianceState.toLowerCase() === 'compliant'
        ).length;
        nonCompliantCounts[type] = typeData.filter(r => 
            r.complianceState.toLowerCase() === 'noncompliant' || 
            r.complianceState.toLowerCase() === 'non-compliant'
        ).length;
    });
    
    // Sort by total count and take top 15
    const sortedTypes = resourceTypes
        .sort((a, b) => 
            (compliantCounts[b] + nonCompliantCounts[b]) - 
            (compliantCounts[a] + nonCompliantCounts[a])
        )
        .slice(0, 15);
    
    if (charts.resourceType) {
        charts.resourceType.destroy();
    }
    
    charts.resourceType = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: sortedTypes.map(type => truncateText(type, 30)),
            datasets: [
                {
                    label: 'Compliant',
                    data: sortedTypes.map(type => compliantCounts[type]),
                    backgroundColor: '#10b981',
                    borderRadius: 6
                },
                {
                    label: 'Non-Compliant',
                    data: sortedTypes.map(type => nonCompliantCounts[type]),
                    backgroundColor: '#ef4444',
                    borderRadius: 6
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        padding: 20,
                        font: { size: 14 }
                    }
                }
            },
            scales: {
                x: {
                    stacked: true,
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                },
                y: {
                    stacked: true,
                    beginAtZero: true,
                    ticks: { precision: 0 }
                }
            }
        }
    });
}

// Compliance by Subscription Chart (Pie)
function renderSubscriptionChart() {
    const ctx = document.getElementById('subscriptionChart');
    
    const subscriptions = [...new Set(filteredData.map(r => r.subscriptionName))].filter(v => v);
    const subscriptionCounts = {};
    
    subscriptions.forEach(sub => {
        subscriptionCounts[sub] = filteredData.filter(r => 
            r.subscriptionName === sub &&
            (r.complianceState.toLowerCase() === 'noncompliant' || 
             r.complianceState.toLowerCase() === 'non-compliant')
        ).length;
    });
    
    const sortedSubs = Object.entries(subscriptionCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);
    
    if (charts.subscription) {
        charts.subscription.destroy();
    }
    
    const colors = [
        '#ef4444', '#f59e0b', '#10b981', '#3b82f6',
        '#8b5cf6', '#ec4899', '#14b8a6', '#f97316'
    ];
    
    charts.subscription = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: sortedSubs.map(([sub]) => truncateText(sub, 25)),
            datasets: [{
                data: sortedSubs.map(([, count]) => count),
                backgroundColor: colors,
                borderWidth: 2,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: { size: 12 }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.label}: ${context.parsed.toLocaleString()} non-compliant`;
                        }
                    }
                }
            }
        }
    });
}

// Trend Chart (Resource Type Distribution)
function renderTrendChart() {
    const ctx = document.getElementById('trendChart');
    
    const resourceTypes = [...new Set(filteredData.map(r => r.resourceType))].filter(v => v);
    const typeCounts = {};
    
    resourceTypes.forEach(type => {
        typeCounts[type] = filteredData.filter(r => r.resourceType === type).length;
    });
    
    const sortedTypes = Object.entries(typeCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    if (charts.trend) {
        charts.trend.destroy();
    }
    
    charts.trend = new Chart(ctx, {
        type: 'line',
        data: {
            labels: sortedTypes.map(([type]) => truncateText(type, 20)),
            datasets: [{
                label: 'Resource Count',
                data: sortedTypes.map(([, count]) => count),
                borderColor: '#0078d4',
                backgroundColor: 'rgba(0, 120, 212, 0.1)',
                tension: 0.4,
                fill: true,
                borderWidth: 3,
                pointRadius: 5,
                pointHoverRadius: 7
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { precision: 0 }
                },
                x: {
                    ticks: {
                        maxRotation: 45,
                        minRotation: 45
                    }
                }
            }
        }
    });
}

// Render Table
function renderTable() {
    const tbody = document.getElementById('tableBody');
    const start = (currentPage - 1) * itemsPerPage;
    const end = start + itemsPerPage;
    const pageData = filteredData.slice(start, end);
    
    tbody.innerHTML = '';
    
    pageData.forEach(item => {
        const row = tbody.insertRow();
        
        row.insertCell(0).textContent = item.resourceName || '-';
        row.insertCell(1).textContent = item.resourceType || '-';
        row.insertCell(2).textContent = item.resourceLocation || '-';
        
        const complianceCell = row.insertCell(3);
        const isCompliant = item.complianceState.toLowerCase() === 'compliant';
        complianceCell.innerHTML = `
            <span class="status-badge ${isCompliant ? 'compliant' : 'non-compliant'}">
                ${isCompliant ? 'Compliant' : 'Non-Compliant'}
            </span>
        `;
        
        const policyCell = row.insertCell(4);
        const policyDisplay = getPolicyDisplayName(item.policyDefinitionName);
        policyCell.innerHTML = `<span class="truncate" title="${item.policyDefinitionName}">${policyDisplay}</span>`;
        
        row.insertCell(5).textContent = item.subscriptionName || '-';
        row.insertCell(6).textContent = item.resourceGroup || '-';
        row.insertCell(7).textContent = item.initiativeDisplayName || '-';
    });
    
    document.getElementById('displayedCount').textContent = filteredData.length.toLocaleString();
    document.getElementById('totalCount').textContent = rawData.length.toLocaleString();
    
    renderPagination();
}

// Render Pagination
function renderPagination() {
    const pagination = document.getElementById('pagination');
    const totalPages = Math.ceil(filteredData.length / itemsPerPage);
    
    if (totalPages <= 1) {
        pagination.innerHTML = '';
        return;
    }
    
    let html = '';
    
    // Previous button
    html += `<button ${currentPage === 1 ? 'disabled' : ''} onclick="changePage(${currentPage - 1})">Previous</button>`;
    
    // Page numbers
    const maxVisiblePages = 7;
    let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
    let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
    
    if (endPage - startPage < maxVisiblePages - 1) {
        startPage = Math.max(1, endPage - maxVisiblePages + 1);
    }
    
    if (startPage > 1) {
        html += `<button onclick="changePage(1)">1</button>`;
        if (startPage > 2) html += '<span>...</span>';
    }
    
    for (let i = startPage; i <= endPage; i++) {
        html += `<button class="${i === currentPage ? 'active' : ''}" onclick="changePage(${i})">${i}</button>`;
    }
    
    if (endPage < totalPages) {
        if (endPage < totalPages - 1) html += '<span>...</span>';
        html += `<button onclick="changePage(${totalPages})">${totalPages}</button>`;
    }
    
    // Next button
    html += `<button ${currentPage === totalPages ? 'disabled' : ''} onclick="changePage(${currentPage + 1})">Next</button>`;
    
    pagination.innerHTML = html;
}

// Change Page
function changePage(page) {
    currentPage = page;
    renderTable();
    document.querySelector('.table-section').scrollIntoView({ behavior: 'smooth' });
}

// Setup Export
function setupExport() {
    document.getElementById('exportBtn')?.addEventListener('click', exportFilteredData);
}

// Export Filtered Data
function exportFilteredData() {
    if (filteredData.length === 0) {
        alert('No data to export');
        return;
    }
    
    const csv = Papa.unparse(filteredData);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    
    link.setAttribute('href', url);
    link.setAttribute('download', `azure-policy-compliance-filtered-${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Utility Functions
function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}
