// Fast Intelligence Engine - Mistral + MCP
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import fs from 'fs/promises';
import path from 'path';

// Unified data schema for intelligence extraction
class IntelligenceSchema {
  constructor() {
    this.data = {
      target: null,
      timestamp: new Date().toISOString(),
      open_ports: [],
      services: {},
      subdomains: [],
      tech_stack: [],
      possible_vulns: [],
      endpoints: [],
      ssl_info: {},
      dns_records: {},
      risk_matrix: {
        high: [],
        medium: [],
        low: []
      },
      summary: {
        total_ports: 0,
        total_services: 0,
        total_subdomains: 0,
        total_vulns: 0,
        risk_score: 0
      }
    };
  }

  addPort(port, service = null) {
    if (!this.data.open_ports.includes(port)) {
      this.data.open_ports.push(port);
    }
    if (service) {
      this.data.services[port] = service;
    }
  }

  addSubdomain(subdomain) {
    if (!this.data.subdomains.includes(subdomain)) {
      this.data.subdomains.push(subdomain);
    }
  }

  addTechnology(tech) {
    if (!this.data.tech_stack.includes(tech)) {
      this.data.tech_stack.push(tech);
    }
  }

  addVulnerability(cve) {
    this.data.possible_vulns.push(cve);
  }

  addEndpoint(endpoint) {
    if (!this.data.endpoints.includes(endpoint)) {
      this.data.endpoints.push(endpoint);
    }
  }

  updateSummary() {
    this.data.summary.total_ports = this.data.open_ports.length;
    this.data.summary.total_services = Object.keys(this.data.services).length;
    this.data.summary.total_subdomains = this.data.subdomains.length;
    this.data.summary.total_vulns = this.data.possible_vulns.length;
    
    // Calculate risk score (0-100)
    let score = 0;
    score += this.data.possible_vulns.length * 10; // Each vuln adds 10 points
    score += this.data.open_ports.length * 2; // Each port adds 2 points
    if (this.data.open_ports.includes(22)) score += 5; // SSH
    if (this.data.open_ports.includes(3389)) score += 10; // RDP
    if (this.data.open_ports.includes(1433)) score += 8; // MSSQL
    if (this.data.open_ports.includes(3306)) score += 6; // MySQL
    
    this.data.summary.risk_score = Math.min(100, score);
  }

  getData() {
    this.updateSummary();
    return this.data;
  }
}

// Parser classes for different recon tools
class NmapParser {
  static parse(output) {
    const intelligence = new IntelligenceSchema();
    
    if (!output) return intelligence;
    
    // Parse port information
    const portMatches = output.match(/(\d+)\/(\w+)\s+(\w+)\s+(.+)/g);
    if (portMatches) {
      portMatches.forEach(match => {
        const parts = match.split(/\s+/);
        const port = parseInt(parts[0].split('/')[0]);
        const protocol = parts[0].split('/')[1];
        const state = parts[1];
        const service = parts[2];
        const version = parts.slice(3).join(' ');
        
        if (state === 'open') {
          intelligence.addPort(port, `${service} ${version}`.trim());
        }
      });
    }
    
    // Parse service versions
    const versionMatches = output.match(/(\w+)\s+(\d+\.\d+\.\d+)/g);
    if (versionMatches) {
      versionMatches.forEach(match => {
        const [service, version] = match.split(' ');
        intelligence.addTechnology(`${service} ${version}`);
      });
    }
    
    return intelligence;
  }
}

class AmassParser {
  static parse(output) {
    const intelligence = new IntelligenceSchema();
    
    if (!output) return intelligence;
    
    // Parse subdomains
    const lines = output.split('\n');
    lines.forEach(line => {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#') && trimmed.includes('.')) {
        intelligence.addSubdomain(trimmed);
      }
    });
    
    return intelligence;
  }

  static parseJson(output) {
    const intelligence = new IntelligenceSchema();
    
    try {
      const data = JSON.parse(output);
      if (Array.isArray(data)) {
        data.forEach(entry => {
          if (entry.name) {
            intelligence.addSubdomain(entry.name);
          }
        });
      }
    } catch (e) {
      // Fallback to text parsing
      return AmassParser.parse(output);
    }
    
    return intelligence;
  }
}

class GobusterParser {
  static parse(output) {
    const intelligence = new IntelligenceSchema();
    
    if (!output) return intelligence;
    
    // Parse discovered directories/endpoints
    const lines = output.split('\n');
    lines.forEach(line => {
      const match = line.match(/(\d+)\s+\((\d+%)\s+\)\s+(.+)/);
      if (match) {
        const statusCode = parseInt(match[1]);
        const endpoint = match[3].trim();
        intelligence.addEndpoint(endpoint);
        
        // Add to risk matrix based on status code
        if (statusCode === 200) {
          intelligence.data.risk_matrix.medium.push(`Exposed endpoint: ${endpoint}`);
        } else if (statusCode === 403) {
          intelligence.data.risk_matrix.low.push(`Forbidden endpoint: ${endpoint}`);
        }
      }
    });
    
    return intelligence;
  }
}

class WhatWebParser {
  static parse(output) {
    const intelligence = new IntelligenceSchema();
    
    if (!output) return intelligence;
    
    // Parse web technologies
    const techMatches = output.match(/\[([^\]]+)\]/g);
    if (techMatches) {
      techMatches.forEach(match => {
        const tech = match.replace(/[\[\]]/g, '');
        intelligence.addTechnology(tech);
      });
    }
    
    // Parse specific technologies
    const patterns = {
      'WordPress': /WordPress/i,
      'Drupal': /Drupal/i,
      'Joomla': /Joomla/i,
      'Laravel': /Laravel/i,
      'Django': /Django/i,
      'React': /React/i,
      'Angular': /Angular/i,
      'Vue.js': /Vue\.js/i,
      'jQuery': /jQuery/i,
      'Bootstrap': /Bootstrap/i,
      'Apache': /Apache/i,
      'Nginx': /nginx/i,
      'IIS': /IIS/i,
      'PHP': /PHP/i,
      'ASP.NET': /ASP\.NET/i,
      'Node.js': /Node\.js/i
    };
    
    Object.entries(patterns).forEach(([tech, pattern]) => {
      if (pattern.test(output)) {
        intelligence.addTechnology(tech);
      }
    });
    
    return intelligence;
  }
}

class SSLScanParser {
  static parse(output) {
    const intelligence = new IntelligenceSchema();
    
    if (!output) return intelligence;
    
    // Parse SSL/TLS information
    const sslInfo = {};
    
    // Certificate information
    const certMatch = output.match(/Subject:\s+(.+)/);
    if (certMatch) {
      sslInfo.subject = certMatch[1].trim();
    }
    
    // Expiry date
    const expiryMatch = output.match(/Not After\s*:\s*(.+)/);
    if (expiryMatch) {
      sslInfo.expiry = expiryMatch[1].trim();
    }
    
    // Cipher suites
    const cipherMatches = output.match(/(\w+)\s+(\w+)\s+(\d+)/g);
    if (cipherMatches) {
      sslInfo.ciphers = cipherMatches.map(c => c.trim());
    }
    
    // Weak ciphers detection
    const weakCiphers = ['RC4', 'DES', '3DES', 'MD5'];
    weakCiphers.forEach(cipher => {
      if (output.includes(cipher)) {
        intelligence.data.risk_matrix.medium.push(`Weak cipher detected: ${cipher}`);
      }
    });
    
    intelligence.data.ssl_info = sslInfo;
    
    return intelligence;
  }
}

class TheHarvesterParser {
  static parse(output) {
    const intelligence = new IntelligenceSchema();
    
    if (!output) return intelligence;
    
    // Parse emails
    const emailMatches = output.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g);
    if (emailMatches) {
      intelligence.data.emails = emailMatches;
    }
    
    // Parse hostnames
    const hostnameMatches = output.match(/\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g);
    if (hostnameMatches) {
      hostnameMatches.forEach(hostname => {
        intelligence.addSubdomain(hostname);
      });
    }
    
    return intelligence;
  }
}

// Main Intelligence Engine
class FastIntelligenceEngine {
  constructor() {
    this.parsers = {
      'nmap': NmapParser,
      'amass': AmassParser,
      'gobuster': GobusterParser,
      'whatweb': WhatWebParser,
      'sslscan': SSLScanParser,
      'theHarvester': TheHarvesterParser
    };
    
    this.intelligence = new IntelligenceSchema();
  }

  async parseToolOutput(toolName, output) {
    const parser = this.parsers[toolName];
    if (!parser) {
      console.log(chalk.yellow(`⚠️  No parser found for tool: ${toolName}`));
      return;
    }
    
    try {
      const parsed = parser.parse(output);
      this.mergeIntelligence(parsed);
      console.log(chalk.green(`✅ Parsed ${toolName} output`));
    } catch (error) {
      console.log(chalk.red(`❌ Failed to parse ${toolName} output: ${error.message}`));
    }
  }

  mergeIntelligence(newIntelligence) {
    const newData = newIntelligence.getData();
    
    // Merge ports and services
    newData.open_ports.forEach(port => {
      this.intelligence.addPort(port, newData.services[port]);
    });
    
    // Merge subdomains
    newData.subdomains.forEach(subdomain => {
      this.intelligence.addSubdomain(subdomain);
    });
    
    // Merge technologies
    newData.tech_stack.forEach(tech => {
      this.intelligence.addTechnology(tech);
    });
    
    // Merge vulnerabilities
    newData.possible_vulns.forEach(vuln => {
      this.intelligence.addVulnerability(vuln);
    });
    
    // Merge endpoints
    newData.endpoints.forEach(endpoint => {
      this.intelligence.addEndpoint(endpoint);
    });
    
    // Merge risk matrix
    Object.keys(newData.risk_matrix).forEach(risk => {
      this.intelligence.data.risk_matrix[risk].push(...newData.risk_matrix[risk]);
    });
    
    // Merge SSL info
    if (Object.keys(newData.ssl_info).length > 0) {
      this.intelligence.data.ssl_info = { ...this.intelligence.data.ssl_info, ...newData.ssl_info };
    }
    
    // Merge DNS records
    if (Object.keys(newData.dns_records).length > 0) {
      this.intelligence.data.dns_records = { ...this.intelligence.data.dns_records, ...newData.dns_records };
    }
  }

  async analyzeWithAI() {
    const data = this.intelligence.getData();
    
    const prompt = `Analyze the following reconnaissance intelligence and provide a comprehensive security assessment:

Target: ${data.target}
Open Ports: ${data.open_ports.join(', ')}
Services: ${JSON.stringify(data.services)}
Technologies: ${data.tech_stack.join(', ')}
Subdomains: ${data.subdomains.join(', ')}
Endpoints: ${data.endpoints.join(', ')}
SSL Info: ${JSON.stringify(data.ssl_info)}

Please provide:
1. Executive Summary (2-3 sentences)
2. Critical Findings (high-risk items)
3. Technology Stack Analysis
4. Attack Surface Assessment
5. Recommended Security Measures
6. Risk Level (Low/Medium/High)

Format as markdown with clear sections.`;

    try {
      const aiResult = await mistral.chat.complete({
        model: "mistral-large-latest",
        messages: [{ role: "user", content: prompt }]
      });
      return aiResult.choices?.[0]?.message?.content;
    } catch (err) {
      return `AI analysis failed: ${err.message}`;
    }
  }

  async generateVulnerabilityAssessment() {
    const data = this.intelligence.getData();
    const vulns = [];
    
    // Check for common vulnerable versions
    const vulnerableVersions = {
      'Apache': {
        '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
        '2.4.50': ['CVE-2021-41773', 'CVE-2021-42013']
      },
      'WordPress': {
        '<5.8': ['CVE-2021-29447', 'CVE-2021-29450'],
        '<5.7': ['CVE-2021-29447', 'CVE-2021-29450', 'CVE-2021-29451']
      },
      'PHP': {
        '<7.4': ['CVE-2021-21708', 'CVE-2021-21707'],
        '<8.0': ['CVE-2021-21708', 'CVE-2021-21707']
      }
    };
    
    data.tech_stack.forEach(tech => {
      Object.entries(vulnerableVersions).forEach(([software, versions]) => {
        if (tech.includes(software)) {
          const versionMatch = tech.match(/(\d+\.\d+\.\d+)/);
          if (versionMatch) {
            const version = versionMatch[1];
            Object.entries(versions).forEach(([vulnVersion, cves]) => {
              if (this.compareVersions(version, vulnVersion)) {
                cves.forEach(cve => {
                  vulns.push({
                    cve: cve,
                    service: software,
                    version: version,
                    severity: 'High',
                    description: `Known vulnerable ${software} version ${version}`
                  });
                });
              }
            });
          }
        }
      });
    });
    
    return vulns;
  }

  compareVersions(version1, version2) {
    const v1 = version1.split('.').map(Number);
    const v2 = version2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(v1.length, v2.length); i++) {
      const num1 = v1[i] || 0;
      const num2 = v2[i] || 0;
      if (num1 < num2) return true;
      if (num1 > num2) return false;
    }
    return false;
  }

  async generateReports() {
    const data = this.intelligence.getData();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportDir = `./reports/${data.target || 'intelligence'}_${timestamp}`;
    
    try {
      await fs.mkdir(reportDir, { recursive: true });
      
      // Generate vulnerability assessment
      const vulns = await this.generateVulnerabilityAssessment();
      data.possible_vulns = vulns;
      
      // Generate AI analysis
      const aiAnalysis = await this.analyzeWithAI();
      
      // JSON intelligence report
      await fs.writeFile(`${reportDir}/intel_summary.json`, JSON.stringify(data, null, 2));
      
      // Markdown summary report
      const markdownReport = `# Fast Intelligence Report: ${data.target}

## Executive Summary
- **Target**: ${data.target}
- **Scan Date**: ${new Date().toISOString()}
- **Risk Score**: ${data.summary.risk_score}/100
- **Total Ports**: ${data.summary.total_ports}
- **Total Services**: ${data.summary.total_services}
- **Total Subdomains**: ${data.summary.total_subdomains}
- **Total Vulnerabilities**: ${data.summary.total_vulns}

## Open Ports and Services
${Object.entries(data.services).map(([port, service]) => `- **Port ${port}**: ${service}`).join('\n')}

## Technology Stack
${data.tech_stack.map(tech => `- ${tech}`).join('\n')}

## Discovered Subdomains
${data.subdomains.map(subdomain => `- ${subdomain}`).join('\n')}

## Endpoints
${data.endpoints.map(endpoint => `- ${endpoint}`).join('\n')}

## Risk Matrix

### High Risk
${data.risk_matrix.high.map(risk => `- ${risk}`).join('\n')}

### Medium Risk
${data.risk_matrix.medium.map(risk => `- ${risk}`).join('\n')}

### Low Risk
${data.risk_matrix.low.map(risk => `- ${risk}`).join('\n')}

## AI Analysis
${aiAnalysis}

## SSL/TLS Information
${Object.entries(data.ssl_info).map(([key, value]) => `- **${key}**: ${value}`).join('\n')}

## Possible Vulnerabilities
${data.possible_vulns.map(vuln => `- **${vuln.cve}**: ${vuln.description} (${vuln.severity})`).join('\n')}
`;
      
      await fs.writeFile(`${reportDir}/summary_report.md`, markdownReport);
      
      // MCP context file
      const mcpContext = {
        target: data.target,
        timestamp: data.timestamp,
        intelligence_data: data,
        next_modules: [
          'Contextual Intelligence Engine',
          'Basic Vuln Extractor',
          'Exploit Finder & Fetcher'
        ]
      };
      
      await fs.writeFile(`${reportDir}/graph_context.mcp`, JSON.stringify(mcpContext, null, 2));
      
      console.log(chalk.green(`\n📊 Intelligence reports generated in: ${reportDir}`));
      return reportDir;
    } catch (err) {
      console.log(chalk.red(`Report generation failed: ${err.message}`));
    }
  }

  async processReconResults(toolOutputs) {
    console.log(chalk.bgBlue.white(`\n🧠 Fast Intelligence Engine - Processing Recon Results`));
    
    this.intelligence.data.target = toolOutputs.target || 'unknown';
    
    // Process each tool output
    for (const [toolName, output] of Object.entries(toolOutputs)) {
      if (output && output.output) {
        await this.parseToolOutput(toolName, output.output);
      }
    }
    
    // Generate comprehensive analysis
    console.log(chalk.bgCyan.black(`\n🤖 AI-Powered Intelligence Analysis`));
    const aiAnalysis = await this.analyzeWithAI();
    console.log(chalk.bgMagenta.white(`\nAI Intelligence Summary:`));
    console.log(aiAnalysis);
    
    // Generate reports
    console.log(chalk.bgGreen.black(`\n📊 Generating Intelligence Reports`));
    const reportDir = await this.generateReports();
    
    console.log(chalk.bgGreen.white(`\n✅ Fast Intelligence Engine completed!`));
    console.log(chalk.yellow(`📁 Reports saved to: ${reportDir}`));
    
    return this.intelligence.getData();
  }
}

export { FastIntelligenceEngine, IntelligenceSchema }; 