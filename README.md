# 🔎 FAST INTELLIGENCE ENGINE - MISTRAL + MCP

A comprehensive reconnaissance and intelligence analysis system powered by **Mistral AI** and utilizing the **Model Context Protocol (MCP)** for advanced security assessment.

## 🎯 Overview

The Fast Intelligence Engine rapidly analyzes reconnaissance tool outputs and extracts meaningful intelligence about a target's attack surface, including services, open ports, technology stack, vulnerabilities, and potential exploits. It provides structured intelligence data that feeds into contextual modules for deeper analysis and exploitation planning.

## 🚀 Features

### Core Capabilities
- **Multi-Tool Reconnaissance**: Integrates with Nmap, Amass, Gobuster, WhatWeb, SSLScan, theHarvester, and more
- **AI-Powered Analysis**: Uses Mistral AI for intelligent correlation and assessment
- **MCP Integration**: Model Context Protocol for chaining intelligence modules
- **Structured Intelligence**: Unified data schema for all reconnaissance results
- **Vulnerability Assessment**: Automatic CVE detection and version analysis
- **Exploit Mapping**: Links vulnerabilities to available exploits
- **Comprehensive Reporting**: Multiple report formats (JSON, Markdown, MCP)

### Intelligence Modules
1. **Fast Intelligence Engine**: Core parsing and intelligence extraction
2. **Contextual Intelligence Engine**: Business impact and attack path analysis
3. **Basic Vuln Extractor**: CVE analysis and vulnerability mapping
4. **Exploit Finder & Fetcher**: Exploit database integration

## 📦 Installation

### Prerequisites
- Node.js 16+ 
- npm or yarn
- Reconnaissance tools (nmap, amass, gobuster, etc.)

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd mschk

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env
# Edit .env and add your MISTRAL_API_KEY

# Install reconnaissance tools (Ubuntu/Debian)
sudo apt update
sudo apt install nmap masscan whatweb gobuster nikto enum4linux snmpwalk ike-scan
```

## 🔧 Configuration

### Environment Variables
Create a `.env` file in the root directory:

```env
MISTRAL_API_KEY=your_mistral_api_key_here
```

### Tool Configuration
The system automatically detects available reconnaissance tools and provides installation guidance for missing tools.

## 🎮 Usage

### Basic Usage
```bash
# Start the reconnaissance system
npm start

# Or run directly
node index.js
```

### Interactive Mode
The system provides three execution modes:
- **Interactive**: Confirm each tool execution
- **Auto-run**: Execute all tools automatically
- **Smart**: Auto-run with intelligent error handling

### Target Input
The system accepts various target formats:
- IP addresses: `192.168.1.1`
- Domains: `example.com`
- URLs: `https://example.com`

## 🏗️ Architecture

### System Flow
```
Target Input → Validation → Reconnaissance → Fast Intelligence → Contextual Analysis → Vulnerability Extraction → Exploit Mapping → Reports
```

### MCP Chain
1. **Reconnaissance Engine**: Executes recon tools
2. **Fast Intelligence Engine**: Parses and normalizes results
3. **Contextual Intelligence Engine**: Business impact analysis
4. **Basic Vuln Extractor**: CVE detection and mapping
5. **Exploit Finder & Fetcher**: Exploit database integration

### Data Schema
```json
{
  "target": "example.com",
  "open_ports": [80, 443, 3306],
  "services": {
    "80": "nginx 1.14",
    "443": "Apache 2.4.49",
    "3306": "MySQL 5.7"
  },
  "tech_stack": ["WordPress", "PHP 7.4", "React"],
  "subdomains": ["dev.example.com", "test.example.com"],
  "possible_vulns": [
    {
      "cve": "CVE-2021-41773",
      "severity": "Critical",
      "service": "Apache",
      "version": "2.4.49"
    }
  ],
  "risk_matrix": {
    "high": [],
    "medium": [],
    "low": []
  }
}
```

## 📊 Output Formats

### Report Types
- **JSON Reports**: Structured data for programmatic analysis
- **Markdown Reports**: Human-readable intelligence summaries
- **MCP Context Files**: Model Context Protocol integration data

### Report Locations
All reports are saved to `./reports/` with timestamped directories:
```
reports/
├── target_2024-01-01T12-00-00-000Z/
│   ├── intel_summary.json
│   ├── summary_report.md
│   ├── graph_context.mcp
│   ├── contextual_intelligence.json
│   ├── contextual_report.md
│   ├── vuln_extraction.json
│   ├── vuln_report.md
│   ├── exploit_finder.json
│   └── exploit_report.md
```

## 🔍 Supported Tools

### Reconnaissance Tools
- **Nmap**: Port scanning and service detection
- **Amass**: Subdomain enumeration
- **Gobuster**: Directory and file enumeration
- **WhatWeb**: Web technology fingerprinting
- **SSLScan**: SSL/TLS analysis
- **theHarvester**: OSINT gathering
- **Subfinder**: Subdomain discovery
- **DNSRecon**: DNS enumeration
- **Nikto**: Web vulnerability scanning
- **Enum4linux**: SMB/NetBIOS enumeration

### Intelligence Parsers
Each tool has a dedicated parser that extracts structured intelligence:
- **NmapParser**: Ports, services, versions
- **AmassParser**: Subdomains, DNS records
- **GobusterParser**: Endpoints, directories
- **WhatWebParser**: Web technologies, frameworks
- **SSLScanParser**: SSL/TLS configuration
- **TheHarvesterParser**: Emails, hostnames

## 🧠 AI Integration

### Mistral AI Features
- **Intelligence Correlation**: Connects findings across tools
- **Risk Assessment**: AI-powered risk scoring
- **Attack Path Analysis**: Identifies potential attack vectors
- **Business Impact Analysis**: Assesses organizational risk
- **Remediation Recommendations**: Prioritized security fixes

### AI Prompts
The system uses carefully crafted prompts for:
- Reconnaissance planning
- Intelligence analysis
- Vulnerability assessment
- Exploit analysis
- Contextual correlation

## 🔒 Security Considerations

### Ethical Usage
- Only use on systems you own or have explicit permission to test
- Respect rate limits and terms of service
- Follow responsible disclosure practices
- Comply with local laws and regulations

### Data Protection
- Reconnaissance results are stored locally
- No data is transmitted to external services (except Mistral AI for analysis)
- Reports can be encrypted or deleted as needed

## 🛠️ Development

### Project Structure
```
mschk/
├── index.js                 # Main entry point
├── validator.js             # Target validation
├── communicatetoUser.js     # User interaction
├── Config/
│   └── Mistra.js           # Mistral AI configuration
├── Recon/
│   ├── Engine.js           # Main reconnaissance engine
│   ├── IntelligenceEngine.js # Fast intelligence engine
│   ├── ContextualEngine.js # Contextual analysis
│   ├── VulnExtractor.js    # Vulnerability extraction
│   ├── ExploitFinder.js    # Exploit database integration
│   ├── Tools.js            # Tool definitions
│   └── Tools/              # Tool-specific modules
└── reports/                # Generated reports
```

### Adding New Tools
1. Add tool to `toolMap` in `Engine.js`
2. Create parser in `IntelligenceEngine.js`
3. Update tool availability check
4. Test with sample output

### Extending Intelligence
1. Modify `IntelligenceSchema` class
2. Add new analysis methods
3. Update AI prompts
4. Extend report generation

## 📈 Performance

### Optimization Features
- **Parallel Processing**: Multiple tools run concurrently
- **Smart Caching**: Avoids redundant tool executions
- **Incremental Analysis**: Builds intelligence progressively
- **Memory Management**: Efficient data structures

### Scalability
- **Modular Design**: Easy to add new tools and parsers
- **MCP Integration**: Supports distributed processing
- **Report Generation**: Handles large datasets efficiently

## 🤝 Contributing

### Development Setup
```bash
# Install development dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test
```

### Code Style
- Use ES6+ features
- Follow JavaScript best practices
- Add comprehensive comments
- Include error handling

### Pull Request Process
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the ISC License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before testing any systems. The authors are not responsible for any misuse of this tool.

## 🆘 Support

### Common Issues
- **Missing Tools**: Install required reconnaissance tools
- **API Errors**: Check Mistral API key configuration
- **Permission Errors**: Ensure proper file permissions
- **Network Issues**: Check firewall and proxy settings

### Getting Help
- Check the documentation
- Review error messages
- Verify tool installations
- Test with simple targets first

---

**Fast Intelligence Engine** - Powered by Mistral AI and MCP for advanced security intelligence. 