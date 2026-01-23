# Azure Policy Compliance Dashboard

An interactive web-based dashboard for visualizing and analyzing Azure Policy compliance reports. This tool helps you understand large CSV reports (50k+ records) with intuitive visualizations, powerful filtering, and detailed data exploration capabilities.

## Features

### 📊 Visual Analytics
- **Summary Cards**: Quick overview of compliant/non-compliant resources, total resources, and active policies
- **Compliance Overview Chart**: Doughnut chart showing compliance distribution
- **Top Non-Compliant Policies**: Horizontal bar chart highlighting the most problematic policies
- **Compliance by Resource Type**: Stacked bar chart showing compliance status across different Azure resource types
- **Compliance by Subscription**: Pie chart showing non-compliant resources distribution across subscriptions
- **Resource Type Distribution**: Line chart showing top resource types by count

### 🔍 Advanced Filtering
- **Compliance State**: Filter by Compliant or Non-Compliant
- **Resource Type**: Filter by specific Azure resource types
- **Subscription**: Filter by Azure subscription
- **Resource Group**: Filter by resource group
- **Policy Definition**: Filter by specific policy (with friendly name translation)
- **Search**: Real-time search across all fields

### 📋 Data Table
- Paginated table showing detailed results (50 items per page)
- Sortable columns with all key information
- Displays resource name, type, location, compliance status, policy, subscription, resource group, and initiative
- Status badges for easy compliance identification

### 💾 Export Functionality
- Export filtered data to CSV
- Maintains all applied filters in the export
- Timestamps for tracking

### 🎨 Modern Design
- Azure-inspired color scheme
- Responsive design for all screen sizes
- Smooth animations and transitions
- Drag-and-drop file upload
- Interactive hover effects

## CSV File Format

The dashboard expects CSV files with the following columns (case-insensitive):

| Column Name | Description | Required |
|-------------|-------------|----------|
| `resourceName` | Name of the Azure resource | Yes |
| `resourceLocation` | Azure region/location | Yes |
| `resourceType` | Type of Azure resource (e.g., Microsoft.Compute/virtualMachines) | Yes |
| `complianceState` | Compliance status (Compliant/NonCompliant) | Yes |
| `policyDefinitionName` | Policy definition ID or name | Yes |
| `subscriptionName` | Azure subscription name | Yes |
| `initiativeDisplayName` | Policy initiative/set name | Optional |
| `resourceGroup` | Resource group name | Yes |

### Alternative Column Names
The dashboard automatically handles various column naming conventions:
- `resourceName`, `ResourceName`, `resource_name`
- `complianceState`, `ComplianceState`, `compliance_state`
- etc.

## Usage

### Getting Started

1. **Open the Dashboard**
   - Open `index.html` in a modern web browser (Chrome, Firefox, Edge, Safari)
   - No server setup required - it's a completely client-side application

2. **Upload Your CSV File**
   - Click "Select File" or drag and drop your Azure Policy CSV report
   - The dashboard will automatically parse and visualize the data
   - Large files (50k+ rows) are handled efficiently

3. **Explore Your Data**
   - View summary statistics in the top cards
   - Analyze charts to identify trends and issues
   - Use filters to drill down into specific areas
   - Search for specific resources or policies
   - Export filtered results for further analysis

### Best Practices

#### For Investigation
1. Start with the **Summary Cards** to understand overall compliance posture
2. Check the **Top Non-Compliant Policies** chart to identify problem areas
3. Use **Compliance by Resource Type** to see which resources need attention
4. Apply filters to narrow down to specific subscriptions or resource groups
5. Use the search feature to find specific resources

#### For Reporting
1. Apply relevant filters for your target scope
2. Take note of the summary statistics
3. Export filtered data for stakeholder reports
4. Use charts to create visual reports (screenshot-friendly)

#### For Remediation
1. Filter by "Non-Compliant" compliance state
2. Group by policy or resource type
3. Identify top violating policies
4. Export filtered data for remediation teams
5. Track progress by re-uploading updated reports

## Policy Name Translation

The dashboard automatically translates Azure Policy GUIDs and IDs into friendly names:
- Extracts names from policy definition paths
- Converts kebab-case and snake_case to Title Case
- Supports custom mappings (edit `policyNameMapping` in `app.js`)

### Adding Custom Policy Mappings

Edit `app.js` and add entries to the `policyNameMapping` object:

```javascript
const policyNameMapping = {
    'audit-vm-managed-disks': 'Audit VMs without Managed Disks',
    'your-policy-id': 'Your Friendly Policy Name',
    // Add more mappings here
};
```

## Technical Details

### Technologies Used
- **HTML5**: Structure and semantics
- **CSS3**: Styling with custom properties and modern layouts
- **JavaScript (ES6+)**: Application logic and data processing
- **Chart.js**: Interactive charts and visualizations
- **PapaParse**: CSV parsing library

### Browser Compatibility
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

### Performance
- Handles 50,000+ rows efficiently
- Debounced search for smooth performance
- Chart rendering optimized with destroy/recreate pattern
- Pagination for large datasets

### Security & Privacy
- **100% Client-Side**: All data processing happens in your browser
- **No Data Transmission**: Your CSV files never leave your computer
- **No Server Required**: No backend infrastructure needed
- **No Tracking**: No analytics or tracking scripts

## File Structure

```
Portal/
├── index.html          # Main HTML structure
├── styles.css          # All styling and design
├── app.js              # Application logic and data processing
└── README.md           # This documentation
```

## Troubleshooting

### CSV File Not Loading
- Ensure the file has the correct column headers
- Check that the file is a valid CSV format
- Try opening the browser console (F12) to see error messages

### Charts Not Displaying
- Ensure you have an internet connection (Chart.js loads from CDN)
- Check browser console for errors
- Try refreshing the page

### Performance Issues with Large Files
- The dashboard is optimized for 50k+ rows, but extremely large files (500k+) may be slow
- Consider filtering data before export if possible
- Close other browser tabs to free up memory

### Filters Not Working
- Click "Reset Filters" to clear all filters
- Ensure you've selected valid filter values
- Try refreshing the page

## Future Enhancements

Potential additions:
- Historical trend analysis (multiple file comparison)
- Custom policy mapping configuration UI
- Advanced sorting options for table
- More chart types (heat maps, treemaps)
- Dark mode theme
- PDF report generation
- Policy recommendation engine

## Support

For issues or questions:
1. Check this README for common solutions
2. Review the browser console for error messages
3. Ensure your CSV file format matches the expected structure

## License

This project is provided as-is for internal use within your organization.

---

**Built for Azure Policy Compliance Analysis** | Version 1.0
