#!/usr/bin/env python3
"""
Comprehensive Security Report Generator
Aggregates results from multiple security tools and generates unified reports
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import xml.etree.ElementTree as ET

try:
    from jinja2 import Template
    import lxml.html
    from bs4 import BeautifulSoup
except ImportError as e:
    print(f"Missing required packages: {e}")
    print("Installing required packages...")
    os.system("pip install jinja2 lxml beautifulsoup4")
    from jinja2 import Template
    import lxml.html
    from bs4 import BeautifulSoup

class SecurityReportGenerator:
    def __init__(self, reports_dir: str):
        self.reports_dir = Path(reports_dir)
        self.aggregated_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'trivy_data': {},
            'zap_data': {},
            'nmap_data': {},
            'dependency_check_data': {},
            'sbom_data': {},
            'summary': {
                'total_vulnerabilities': 0,
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'info_count': 0
            },
            'risk_score': 0,
            'compliance_status': 'UNKNOWN'
        }
    
    def parse_trivy_report(self) -> Dict[str, Any]:
        """Parse Trivy JSON report"""
        trivy_file = self.reports_dir / 'trivy' / 'trivy-report.json'
        if not trivy_file.exists():
            return {}
        
        try:
            with open(trivy_file, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = []
            total_vulns = 0
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            
            if 'Results' in data:
                for result in data['Results']:
                    if 'Vulnerabilities' in result:
                        for vuln in result['Vulnerabilities']:
                            vulnerabilities.append({
                                'id': vuln.get('VulnerabilityID', 'N/A'),
                                'severity': vuln.get('Severity', 'UNKNOWN'),
                                'title': vuln.get('Title', 'N/A'),
                                'description': vuln.get('Description', 'N/A')[:200] + '...',
                                'package': vuln.get('PkgName', 'N/A'),
                                'installed_version': vuln.get('InstalledVersion', 'N/A'),
                                'fixed_version': vuln.get('FixedVersion', 'N/A')
                            })
                            severity = vuln.get('Severity', 'LOW')
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            total_vulns += 1
            
            # Update summary counts
            self.aggregated_data['summary']['critical_count'] += severity_counts['CRITICAL']
            self.aggregated_data['summary']['high_count'] += severity_counts['HIGH']
            self.aggregated_data['summary']['medium_count'] += severity_counts['MEDIUM']
            self.aggregated_data['summary']['low_count'] += severity_counts['LOW']
            self.aggregated_data['summary']['total_vulnerabilities'] += total_vulns
            
            return {
                'vulnerabilities': vulnerabilities,
                'total_count': total_vulns,
                'severity_counts': severity_counts,
                'scan_target': data.get('ArtifactName', 'Unknown'),
                'scan_type': data.get('ArtifactType', 'Unknown')
            }
        except Exception as e:
            print(f"Error parsing Trivy report: {e}")
            return {}
    
    def parse_zap_report(self) -> Dict[str, Any]:
        """Parse OWASP ZAP JSON report"""
        zap_files = [
            self.reports_dir / 'zap' / 'zap-baseline-report.json',
            self.reports_dir / 'zap' / 'zap-full-report.json'
        ]
        
        combined_data = {
            'alerts': [],
            'total_alerts': 0,
            'risk_counts': {'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        }
        
        for zap_file in zap_files:
            if not zap_file.exists():
                continue
                
            try:
                with open(zap_file, 'r') as f:
                    data = json.load(f)
                
                if 'site' in data:
                    for site in data['site']:
                        if 'alerts' in site:
                            for alert in site['alerts']:
                                combined_data['alerts'].append({
                                    'name': alert.get('name', 'N/A'),
                                    'risk': alert.get('riskdesc', 'Unknown'),
                                    'confidence': alert.get('confidence', 'Unknown'),
                                    'description': alert.get('desc', 'N/A')[:200] + '...',
                                    'solution': alert.get('solution', 'N/A')[:200] + '...',
                                    'reference': alert.get('reference', 'N/A'),
                                    'instances': len(alert.get('instances', []))
                                })
                                
                                risk_level = alert.get('riskdesc', '').split(' ')[0]
                                if risk_level in combined_data['risk_counts']:
                                    combined_data['risk_counts'][risk_level] += 1
                                combined_data['total_alerts'] += 1
            except Exception as e:
                print(f"Error parsing ZAP report {zap_file}: {e}")
        
        return combined_data
    
    def parse_nmap_report(self) -> Dict[str, Any]:
        """Parse Nmap XML report"""
        nmap_file = self.reports_dir / 'nmap' / 'nmap-report.xml'
        if not nmap_file.exists():
            return {}
        
        try:
            tree = ET.parse(nmap_file)
            root = tree.getroot()
            
            hosts = []
            total_ports = 0
            open_ports = 0
            
            for host in root.findall('host'):
                host_info = {
                    'ip': '',
                    'hostname': '',
                    'status': '',
                    'ports': [],
                    'os': '',
                    'scripts': []
                }
                
                # Get IP address
                address = host.find('address[@addrtype="ipv4"]')
                if address is not None:
                    host_info['ip'] = address.get('addr', '')
                
                # Get hostname
                hostnames = host.find('hostnames')
                if hostnames is not None:
                    hostname = hostnames.find('hostname')
                    if hostname is not None:
                        host_info['hostname'] = hostname.get('name', '')
                
                # Get host status
                status = host.find('status')
                if status is not None:
                    host_info['status'] = status.get('state', '')
                
                # Get ports
                ports = host.find('ports')
                if ports is not None:
                    for port in ports.findall('port'):
                        port_info = {
                            'number': port.get('portid', ''),
                            'protocol': port.get('protocol', ''),
                            'state': '',
                            'service': '',
                            'version': ''
                        }
                        
                        state = port.find('state')
                        if state is not None:
                            port_info['state'] = state.get('state', '')
                            if port_info['state'] == 'open':
                                open_ports += 1
                        
                        service = port.find('service')
                        if service is not None:
                            port_info['service'] = service.get('name', '')
                            port_info['version'] = service.get('version', '')
                        
                        host_info['ports'].append(port_info)
                        total_ports += 1
                
                # Get OS information
                os_element = host.find('os')
                if os_element is not None:
                    osmatch = os_element.find('osmatch')
                    if osmatch is not None:
                        host_info['os'] = osmatch.get('name', '')
                
                hosts.append(host_info)
            
            return {
                'hosts': hosts,
                'total_hosts': len(hosts),
                'total_ports': total_ports,
                'open_ports': open_ports,
                'scan_time': root.get('startstr', '')
            }
        except Exception as e:
            print(f"Error parsing Nmap report: {e}")
            return {}
    
    def parse_dependency_check_report(self) -> Dict[str, Any]:
        """Parse OWASP Dependency Check JSON report"""
        dep_file = self.reports_dir / 'dependency-check' / 'dependency-check-report.json'
        if not dep_file.exists():
            return {}
        
        try:
            with open(dep_file, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = []
            total_deps = len(data.get('dependencies', []))
            vulnerable_deps = 0
            
            for dependency in data.get('dependencies', []):
                if 'vulnerabilities' in dependency:
                    vulnerable_deps += 1
                    for vuln in dependency['vulnerabilities']:
                        vulnerabilities.append({
                            'name': vuln.get('name', 'N/A'),
                            'severity': vuln.get('severity', 'UNKNOWN'),
                            'description': vuln.get('description', 'N/A')[:200] + '...',
                            'dependency': dependency.get('fileName', 'N/A'),
                            'cwe': vuln.get('cwe', 'N/A'),
                            'cvss_score': vuln.get('cvssv3', {}).get('baseScore', 0)
                        })
            
            return {
                'vulnerabilities': vulnerabilities,
                'total_dependencies': total_deps,
                'vulnerable_dependencies': vulnerable_deps,
                'total_vulnerabilities': len(vulnerabilities)
            }
        except Exception as e:
            print(f"Error parsing Dependency Check report: {e}")
            return {}
    
    def parse_sbom_data(self) -> Dict[str, Any]:
        """Parse SBOM data"""
        sbom_file = self.reports_dir / 'sbom' / 'sbom.json'
        if not sbom_file.exists():
            return {}
        
        try:
            with open(sbom_file, 'r') as f:
                data = json.load(f)
            
            packages = []
            if 'artifacts' in data:
                for artifact in data['artifacts']:
                    packages.append({
                        'name': artifact.get('name', 'N/A'),
                        'version': artifact.get('version', 'N/A'),
                        'type': artifact.get('type', 'N/A'),
                        'language': artifact.get('language', 'N/A')
                    })
            
            return {
                'total_packages': len(packages),
                'packages': packages[:50],  # Limit to first 50 for display
                'scan_target': data.get('source', {}).get('target', 'Unknown')
            }
        except Exception as e:
            print(f"Error parsing SBOM data: {e}")
            return {}
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on findings"""
        score = 0
        
        # Weight factors
        critical_weight = 10
        high_weight = 7
        medium_weight = 4
        low_weight = 1
        
        # Calculate weighted score
        score += self.aggregated_data['summary']['critical_count'] * critical_weight
        score += self.aggregated_data['summary']['high_count'] * high_weight
        score += self.aggregated_data['summary']['medium_count'] * medium_weight
        score += self.aggregated_data['summary']['low_count'] * low_weight
        
        # Normalize to 0-100 scale (arbitrary max of 200 points)
        normalized_score = min(score / 2, 100)
        
        return round(normalized_score, 2)
    
    def determine_compliance_status(self) -> str:
        """Determine overall compliance status"""
        critical = self.aggregated_data['summary']['critical_count']
        high = self.aggregated_data['summary']['high_count']
        risk_score = self.aggregated_data['risk_score']
        
        if critical > 0:
            return 'NON_COMPLIANT'
        elif high > 10 or risk_score > 70:
            return 'NEEDS_ATTENTION'
        elif high > 5 or risk_score > 40:
            return 'ACCEPTABLE_RISK'
        else:
            return 'COMPLIANT'
    
    def generate_html_report(self) -> str:
        """Generate comprehensive HTML report"""
        template_content = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cybersecurity Risk Assessment Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header .subtitle {
            margin-top: 10px;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 5px solid #667eea;
        }
        .summary-card h3 {
            margin: 0 0 15px 0;
            color: #667eea;
            font-size: 1.2em;
        }
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .critical { color: #dc3545; border-left-color: #dc3545; }
        .high { color: #fd7e14; border-left-color: #fd7e14; }
        .medium { color: #ffc107; border-left-color: #ffc107; }
        .low { color: #28a745; border-left-color: #28a745; }
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .section-header {
            background: #667eea;
            color: white;
            padding: 20px;
            font-size: 1.3em;
            font-weight: 500;
        }
        .section-content {
            padding: 20px;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .table th,
        .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .table th {
            background-color: #f8f9fa;
            font-weight: 600;
        }
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            color: white;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; color: #000; }
        .severity-low { background-color: #28a745; }
        .compliance-status {
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }
        .compliance-compliant { background-color: #d4edda; color: #155724; }
        .compliance-acceptable { background-color: #fff3cd; color: #856404; }
        .compliance-attention { background-color: #f8d7da; color: #721c24; }
        .compliance-non-compliant { background-color: #f5c6cb; color: #721c24; }
        .risk-meter {
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 20px 0;
        }
        .risk-score {
            font-size: 3em;
            font-weight: bold;
            margin-right: 20px;
        }
        .risk-description {
            font-size: 1.2em;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            border-top: 1px solid #ddd;
        }
        .no-data {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Cybersecurity Risk Assessment Report</h1>
            <div class="subtitle">Generated on {{ data.scan_timestamp }}</div>
        </div>

        <div class="summary-grid">
            <div class="summary-card critical">
                <h3>Critical Vulnerabilities</h3>
                <div class="value">{{ data.summary.critical_count }}</div>
            </div>
            <div class="summary-card high">
                <h3>High Vulnerabilities</h3>
                <div class="value">{{ data.summary.high_count }}</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium Vulnerabilities</h3>
                <div class="value">{{ data.summary.medium_count }}</div>
            </div>
            <div class="summary-card low">
                <h3>Low Vulnerabilities</h3>
                <div class="value">{{ data.summary.low_count }}</div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">📊 Overall Risk Assessment</div>
            <div class="section-content">
                <div class="risk-meter">
                    <div class="risk-score" style="color: {% if data.risk_score >= 70 %}#dc3545{% elif data.risk_score >= 40 %}#fd7e14{% else %}#28a745{% endif %};">
                        {{ data.risk_score }}
                    </div>
                    <div class="risk-description">
                        Risk Score (0-100)<br>
                        <small>Based on vulnerability severity and count</small>
                    </div>
                </div>
                <div class="compliance-status compliance-{{ data.compliance_status.lower().replace('_', '-') }}">
                    Compliance Status: {{ data.compliance_status.replace('_', ' ') }}
                </div>
            </div>
        </div>

        {% if data.trivy_data %}
        <div class="section">
            <div class="section-header">🐳 Container Security (Trivy)</div>
            <div class="section-content">
                <p><strong>Scan Target:</strong> {{ data.trivy_data.scan_target }}</p>
                <p><strong>Total Vulnerabilities:</strong> {{ data.trivy_data.total_count }}</p>
                
                {% if data.trivy_data.vulnerabilities %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Vulnerability ID</th>
                            <th>Severity</th>
                            <th>Package</th>
                            <th>Installed Version</th>
                            <th>Fixed Version</th>
                            <th>Title</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vuln in data.trivy_data.vulnerabilities[:20] %}
                        <tr>
                            <td>{{ vuln.id }}</td>
                            <td><span class="severity-badge severity-{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></td>
                            <td>{{ vuln.package }}</td>
                            <td>{{ vuln.installed_version }}</td>
                            <td>{{ vuln.fixed_version or 'N/A' }}</td>
                            <td>{{ vuln.title }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="no-data">No vulnerabilities found</div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if data.zap_data %}
        <div class="section">
            <div class="section-header">⚡ Web Application Security (OWASP ZAP)</div>
            <div class="section-content">
                <p><strong>Total Alerts:</strong> {{ data.zap_data.total_alerts }}</p>
                
                {% if data.zap_data.alerts %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Alert Name</th>
                            <th>Risk Level</th>
                            <th>Confidence</th>
                            <th>Instances</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for alert in data.zap_data.alerts[:15] %}
                        <tr>
                            <td>{{ alert.name }}</td>
                            <td><span class="severity-badge severity-{{ alert.risk.split()[0].lower() }}">{{ alert.risk }}</span></td>
                            <td>{{ alert.confidence }}</td>
                            <td>{{ alert.instances }}</td>
                            <td>{{ alert.description }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="no-data">No security alerts found</div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if data.nmap_data %}
        <div class="section">
            <div class="section-header">🌐 Network Security (Nmap)</div>
            <div class="section-content">
                <p><strong>Hosts Scanned:</strong> {{ data.nmap_data.total_hosts }}</p>
                <p><strong>Open Ports:</strong> {{ data.nmap_data.open_ports }} / {{ data.nmap_data.total_ports }}</p>
                
                {% if data.nmap_data.hosts %}
                {% for host in data.nmap_data.hosts %}
                <h4>Host: {{ host.ip }} ({{ host.hostname or 'Unknown' }})</h4>
                <p><strong>Status:</strong> {{ host.status }}</p>
                <p><strong>OS:</strong> {{ host.os or 'Unknown' }}</p>
                
                {% if host.ports %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for port in host.ports %}
                        <tr>
                            <td>{{ port.number }}</td>
                            <td>{{ port.protocol }}</td>
                            <td>{{ port.state }}</td>
                            <td>{{ port.service }}</td>
                            <td>{{ port.version }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% endif %}
                {% endfor %}
                {% else %}
                <div class="no-data">No network data available</div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if data.dependency_check_data %}
        <div class="section">
            <div class="section-header">📦 Dependency Security (OWASP Dependency Check)</div>
            <div class="section-content">
                <p><strong>Total Dependencies:</strong> {{ data.dependency_check_data.total_dependencies }}</p>
                <p><strong>Vulnerable Dependencies:</strong> {{ data.dependency_check_data.vulnerable_dependencies }}</p>
                
                {% if data.dependency_check_data.vulnerabilities %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Vulnerability</th>
                            <th>Severity</th>
                            <th>CVSS Score</th>
                            <th>Dependency</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for vuln in data.dependency_check_data.vulnerabilities[:15] %}
                        <tr>
                            <td>{{ vuln.name }}</td>
                            <td><span class="severity-badge severity-{{ vuln.severity.lower() }}">{{ vuln.severity }}</span></td>
                            <td>{{ vuln.cvss_score }}</td>
                            <td>{{ vuln.dependency }}</td>
                            <td>{{ vuln.description }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="no-data">No dependency vulnerabilities found</div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        {% if data.sbom_data %}
        <div class="section">
            <div class="section-header">📋 Software Bill of Materials (SBOM)</div>
            <div class="section-content">
                <p><strong>Total Packages:</strong> {{ data.sbom_data.total_packages }}</p>
                <p><strong>Scan Target:</strong> {{ data.sbom_data.scan_target }}</p>
                
                {% if data.sbom_data.packages %}
                <table class="table">
                    <thead>
                        <tr>
                            <th>Package Name</th>
                            <th>Version</th>
                            <th>Type</th>
                            <th>Language</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for package in data.sbom_data.packages %}
                        <tr>
                            <td>{{ package.name }}</td>
                            <td>{{ package.version }}</td>
                            <td>{{ package.type }}</td>
                            <td>{{ package.language }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="no-data">No SBOM data available</div>
                {% endif %}
            </div>
        </div>
        {% endif %}

        <div class="footer">
            <p>Report generated by Automated Cybersecurity Risk Assessment Framework</p>
            <p>Powered by Trivy, OWASP ZAP, OWASP Dependency Check, Nmap, and Syft</p>
        </div>
    </div>
</body>
</html>
        '''
        
        template = Template(template_content)
        return template.render(data=self.aggregated_data)
    
    def run(self):
        """Main execution method"""
        print("🔍 Parsing security tool outputs...")
        
        # Parse all reports
        self.aggregated_data['trivy_data'] = self.parse_trivy_report()
        self.aggregated_data['zap_data'] = self.parse_zap_report()
        self.aggregated_data['nmap_data'] = self.parse_nmap_report()
        self.aggregated_data['dependency_check_data'] = self.parse_dependency_check_report()
        self.aggregated_data['sbom_data'] = self.parse_sbom_data()
        
        # Calculate risk metrics
        self.aggregated_data['risk_score'] = self.calculate_risk_score()
        self.aggregated_data['compliance_status'] = self.determine_compliance_status()
        
        print("📊 Generating comprehensive security report...")
        
        # Generate HTML report
        html_content = self.generate_html_report()
        
        # Save aggregated report
        aggregated_dir = self.reports_dir / 'aggregated'
        aggregated_dir.mkdir(exist_ok=True)
        
        # Save HTML report
        html_file = aggregated_dir / 'comprehensive-security-report.html'
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Save JSON summary
        json_file = aggregated_dir / 'security-summary.json'
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(self.aggregated_data, f, indent=2, default=str)
        
        print(f"✅ Reports generated:")
        print(f"   📄 HTML Report: {html_file}")
        print(f"   📊 JSON Summary: {json_file}")
        print(f"🎯 Risk Score: {self.aggregated_data['risk_score']}")
        print(f"🚦 Compliance Status: {self.aggregated_data['compliance_status']}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python generate-security-report.py <reports_directory>")
        sys.exit(1)
    
    reports_dir = sys.argv[1]
    generator = SecurityReportGenerator(reports_dir)
    generator.run()

if __name__ == "__main__":
    main()
