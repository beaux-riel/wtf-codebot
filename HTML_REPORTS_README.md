# Interactive HTML Report Generation

Transform JSON findings and dependency analysis into interactive HTML reports with comprehensive visualizations using Jinja2, Chart.js, and Plotly.

## 🎯 Overview

This module provides powerful tools to convert JSON analysis data into rich, interactive HTML reports featuring:

- **Executive Dashboards** with key metrics and risk indicators
- **Interactive Charts** using Chart.js and Plotly.js
- **3D Dependency Graphs** for visualization of complex relationships
- **Technical Debt Heatmaps** for identifying problematic areas
- **Security Risk Matrices** for compliance and vulnerability tracking
- **Filterable Data Tables** with advanced search and sorting
- **Responsive Design** that works on desktop and mobile devices

## 🚀 Quick Start

### Basic HTML Report

```python
from html_report_generator import InteractiveHTMLReporter

reporter = InteractiveHTMLReporter()
report_path = reporter.generate_interactive_report(
    findings_json_path="findings.json",
    dependencies_json_path="dependencies.json",
    output_path="report.html",
    title="My Code Analysis Report"
)
print(f"Report generated: {report_path}")
```

### Enhanced HTML Report with Plotly

```python
from enhanced_html_reporter import EnhancedHTMLReporter

reporter = EnhancedHTMLReporter()
report_path = reporter.generate_enhanced_report(
    findings_json_path="findings.json", 
    dependencies_json_path="dependencies.json",
    output_path="enhanced_report.html",
    title="Advanced Analysis Report"
)
print(f"Enhanced report generated: {report_path}")
```

## 📊 Features Comparison

| Feature | Basic Report | Enhanced Report |
|---------|:------------:|:---------------:|
| Bootstrap Styling | ✅ | ✅ |
| Responsive Design | ✅ | ✅ |
| Chart.js Charts | ✅ | ✅ |
| DataTables | ✅ | ✅ |
| Vis.js Network Graph | ✅ | ✅ |
| Interactive Modals | ✅ | ✅ |
| Basic Filtering | ✅ | ✅ |
| Executive Dashboard | ✅ | ✅ |
| **Plotly.js Charts** | ❌ | ✅ |
| **3D Visualizations** | ❌ | ✅ |
| **Heatmaps** | ❌ | ✅ |
| **Sunburst Charts** | ❌ | ✅ |
| **Advanced Analytics Tab** | ❌ | ✅ |
| **Global Filtering** | ❌ | ✅ |
| **Chart Export** | ❌ | ✅ |
| **Trend Analysis** | ❌ | ✅ |
| **Security Matrix** | ❌ | ✅ |
| **Interactive Controls** | ❌ | ✅ |

## 🎨 Report Components

### 1. Executive Dashboard
- **Key Metrics**: Total findings, affected files, quality score, risk level
- **Trend Indicators**: Visual indicators for improvement/degradation
- **Quality Grade**: A-F grading system based on findings severity
- **Security Score**: Real-time security assessment

### 2. Interactive Charts
- **Severity Distribution**: Pie/doughnut charts showing issue severity breakdown
- **Finding Types**: Bar charts categorizing different types of issues
- **Files with Issues**: Horizontal bar charts highlighting problematic files
- **Technical Debt Timeline**: Line charts showing debt accumulation over time

### 3. Advanced Analytics (Enhanced Reports Only)
- **Technical Debt Heatmap**: Interactive heatmap showing debt by file/severity/type
- **Quality Trends**: Multi-axis trend analysis with overlaid metrics
- **3D Dependency Network**: 3D scatter plots of dependency relationships
- **Complexity Sunburst**: Hierarchical breakdown of issue complexity
- **Security Risk Matrix**: Heatmap matrix of security vulnerabilities

### 4. Data Tables
- **Findings Table**: Sortable, filterable table of all findings with details
- **Dependencies Table**: Complete dependency information with licenses
- **Interactive Details**: Click-through modals with comprehensive information
- **Advanced Filtering**: Global filters affecting all visualizations

### 5. Dependency Visualization
- **2D Network Graph**: Interactive network using vis.js
- **3D Network Graph**: Advanced 3D visualization using Plotly
- **Node Details**: Click-to-view dependency information
- **Export Capabilities**: Save graphs as images

## 🔧 Customization

### Custom Templates

```python
from html_report_generator import InteractiveHTMLReporter

# Use custom template directory
reporter = InteractiveHTMLReporter(template_dir="my_templates")

# Customize templates:
# my_templates/
# ├── main_report.html     # Main HTML structure
# ├── charts.html          # Chart components
# ├── tables.html          # Data table components
# ├── dependencies.html    # Dependency visualization
# └── styles.css           # Custom styling
```

### Template Files

#### `main_report.html`
Main HTML structure with navigation, dashboard, and tab content.

#### `charts.html`
Chart components using Chart.js for basic visualizations.

#### `tables.html`
DataTables implementation with filtering and sorting.

#### `dependencies.html`
Dependency network graph and details table.

#### `styles.css`
Custom CSS styling for branding and layout.

### Custom Styling

```css
/* Override default colors */
.metric-card {
    background: linear-gradient(135deg, #your-color-1 0%, #your-color-2 100%);
}

/* Custom chart colors */
.card-header {
    background: linear-gradient(135deg, #your-brand-color 0%, #accent-color 100%);
}
```

### Custom Data Processing

```python
class CustomHTMLReporter(InteractiveHTMLReporter):
    def _calculate_metrics(self, findings_data, dependencies_data):
        # Override to add custom metrics
        base_metrics = super()._calculate_metrics(findings_data, dependencies_data)
        
        # Add custom calculations
        base_metrics['custom_score'] = self._calculate_custom_score(findings_data)
        
        return base_metrics
    
    def _calculate_custom_score(self, findings_data):
        # Your custom scoring logic
        return 95.5
```

## 📋 JSON Schema Requirements

### Findings JSON Structure

```json
{
  "findings": [
    {
      "id": "finding-001",
      "title": "Issue Title",
      "severity": "critical|high|medium|low|info",
      "finding_type": "security_vulnerability|code_smell|...",
      "description": "Detailed description",
      "location": {
        "file_path": "/path/to/file.py",
        "line_start": 45,
        "line_end": 47,
        "function_name": "function_name",
        "class_name": "ClassName"
      },
      "confidence": 0.95,
      "technical_debt_score": 8.5,
      "business_impact": "high|medium|low",
      "effort_to_fix": "high|medium|low",
      "security_info": {
        "cwe_ids": ["CWE-89"],
        "owasp_categories": ["A03:2021 – Injection"]
      },
      "remediation": {
        "description": "How to fix",
        "priority": "immediate|high|medium|low"
      }
    }
  ],
  "quality_metrics": {
    "overall_score": 75.0,
    "grade": "B"
  },
  "risk_assessment": {
    "overall_risk_level": "medium"
  }
}
```

### Dependencies JSON Structure

```json
{
  "summary": {
    "total_dependencies": 67,
    "total_vulnerabilities": 0,
    "license_distribution": {
      "MIT": 25,
      "Apache-2.0": 15
    }
  },
  "results": [
    {
      "package_manager": "pip",
      "file_path": "/requirements.txt",
      "dependencies": {
        "package_name": {
          "name": "package_name",
          "version": "1.0.0",
          "license": "MIT",
          "description": "Package description",
          "dev_dependency": false
        }
      }
    }
  ]
}
```

## 🎮 Interactive Features

### Global Filtering
- **Severity Filter**: Filter by critical, high, medium, low, info
- **Date Range Filter**: Last 7, 30, 90 days or all time
- **File Pattern Filter**: Search by file path or name
- **Type Filter**: Filter by finding type

### Chart Interactions
- **Hover Details**: Rich tooltips with contextual information
- **Click-through**: Navigate to detailed views
- **Zoom/Pan**: Explore large datasets interactively
- **Export**: Save charts as PNG, SVG, or PDF

### Table Features
- **Multi-column Sorting**: Sort by multiple criteria
- **Global Search**: Search across all columns
- **Column Filtering**: Individual column filter dropdowns
- **Pagination**: Handle large datasets efficiently
- **Responsive Design**: Mobile-friendly table views

## 🔄 Integration Examples

### CI/CD Pipeline Integration

```yaml
# .github/workflows/code-analysis.yml
name: Code Analysis Report
on: [push, pull_request]

jobs:
  analysis:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Run Code Analysis
        run: |
          # Your analysis tools here
          python -m wtf_codebot analyze --output findings.json
          python -m wtf_codebot deps --output dependencies.json
      
      - name: Generate HTML Report
        run: |
          python -c "
          from enhanced_html_reporter import EnhancedHTMLReporter
          reporter = EnhancedHTMLReporter()
          reporter.generate_enhanced_report(
              'findings.json', 
              'dependencies.json',
              'report.html',
              'CI/CD Analysis Report'
          )"
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: analysis-report
          path: report.html
```

### Jupyter Notebook Integration

```python
from IPython.display import HTML, display
from enhanced_html_reporter import EnhancedHTMLReporter

# Generate report
reporter = EnhancedHTMLReporter()
report_path = reporter.generate_enhanced_report(
    findings_json_path="analysis_results.json",
    output_path="notebook_report.html",
    title="Jupyter Analysis Report"
)

# Display in notebook
with open(report_path, 'r') as f:
    display(HTML(f.read()))
```

### Web Application Integration

```python
from flask import Flask, render_template_string
from enhanced_html_reporter import EnhancedHTMLReporter

app = Flask(__name__)

@app.route('/analysis-report')
def analysis_report():
    reporter = EnhancedHTMLReporter()
    
    # Generate report content (without file writing)
    html_content = reporter.generate_interactive_report(
        findings_json_path="latest_findings.json",
        title="Live Analysis Dashboard"
    )
    
    return html_content

if __name__ == '__main__':
    app.run(debug=True)
```

## 🛠️ Dependencies

### Required Libraries
```bash
pip install jinja2>=3.0.0
```

### Included via CDN
- **Bootstrap 5.1.3**: UI framework and responsive design
- **Chart.js**: Basic charts and visualizations
- **Plotly.js**: Advanced 3D and interactive charts
- **Vis.js**: Network graph visualization
- **jQuery 3.6.0**: DOM manipulation
- **DataTables 1.13.4**: Advanced table functionality
- **Font Awesome 6.0.0**: Icons and visual elements

## 🎯 Use Cases

### 1. Development Teams
- **Daily Standup Reports**: Quick overview of code quality
- **Sprint Reviews**: Track technical debt and improvements
- **Code Review Preparation**: Identify areas needing attention

### 2. Engineering Management
- **Executive Dashboards**: High-level quality and risk metrics
- **Team Performance**: Compare quality across teams/projects
- **Resource Planning**: Understand effort required for improvements

### 3. DevOps/Platform Teams
- **CI/CD Integration**: Automated quality gates
- **Release Planning**: Risk assessment for deployments
- **Dependency Management**: Track library updates and vulnerabilities

### 4. Security Teams
- **Vulnerability Assessment**: Interactive security findings
- **Compliance Reporting**: CWE/OWASP mapping and tracking
- **Risk Prioritization**: Visual risk matrices and trends

### 5. Architecture Teams
- **Dependency Analysis**: Visualize complex relationships
- **Technical Debt Management**: Track and prioritize improvements
- **Design Reviews**: Identify architectural anti-patterns

## 🧪 Testing

Run the demo to test all functionality:

```bash
python demo_html_reports.py
```

This will generate sample reports demonstrating all features:
- Basic interactive report
- Enhanced report with Plotly
- Custom configuration example

## 📁 File Structure

```
wtf-codebot/
├── html_report_generator.py      # Basic HTML reporter
├── enhanced_html_reporter.py     # Enhanced reporter with Plotly
├── demo_html_reports.py          # Demonstration script
├── templates/                    # Jinja2 templates
│   ├── main_report.html         # Main HTML structure
│   ├── charts.html              # Chart components
│   ├── tables.html              # Data tables
│   ├── dependencies.html        # Dependency graphs
│   └── styles.css               # CSS styling
└── reports/                     # Generated reports
    ├── interactive_report.html
    ├── enhanced_interactive_report.html
    └── sample_*.json            # Sample data files
```

## 📈 Performance Considerations

### Large Datasets
- **Pagination**: DataTables handles large finding lists efficiently
- **Lazy Loading**: Charts render on-demand when tabs are activated
- **Data Filtering**: Client-side filtering for responsive interactions
- **Chunked Processing**: Large dependency graphs are rendered progressively

### Browser Compatibility
- **Modern Browsers**: Chrome 80+, Firefox 75+, Safari 13+, Edge 80+
- **Mobile Support**: Responsive design works on tablets and phones
- **Progressive Enhancement**: Core functionality works without JavaScript

### File Size Optimization
- **CDN Assets**: External libraries loaded from CDN
- **Minified Templates**: Production templates can be minified
- **Image Optimization**: Charts rendered as vector graphics when possible

## 🤝 Contributing

### Adding New Visualizations

1. **Extend the data processing methods**:
```python
def _prepare_custom_chart_data(self, findings_data):
    # Process data for your custom chart
    return chart_data
```

2. **Add template components**:
```html
<!-- In charts.html -->
<div class="col-md-6">
    <div class="card">
        <div class="card-header">
            <h6>Custom Chart</h6>
        </div>
        <div class="card-body">
            <canvas id="customChart"></canvas>
        </div>
    </div>
</div>
```

3. **Implement JavaScript**:
```javascript
function initializeCustomChart() {
    const ctx = document.getElementById('customChart');
    new Chart(ctx, {
        type: 'custom',
        data: reportData.charts.custom_data,
        options: { /* chart options */ }
    });
}
```

### Custom Filters

```python
def _add_custom_filters(self):
    """Add custom Jinja2 filters."""
    self.env.filters['custom_format'] = self._custom_format_filter
    
def _custom_format_filter(self, value):
    """Custom formatting logic."""
    return formatted_value
```

## 📞 Support

For questions, issues, or contributions:

1. **Check existing reports**: Review generated samples for examples
2. **Read the source**: Code is extensively documented
3. **Run demos**: Use `demo_html_reports.py` to understand functionality
4. **Customize templates**: Modify templates for specific needs

## 📝 License

This HTML reporting functionality is part of the WTF Codebot project and follows the same licensing terms.

---

**Ready to transform your JSON analysis data into beautiful, interactive reports? Start with the quick start examples above!** 🚀
