// Basic Vuln Extractor - CVE Analysis & Exploit Mapping
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import fs from 'fs/promises';

class BasicVulnExtractor {
  constructor() {
    this.vulnDatabase = {
      // Common vulnerable versions and their CVEs
      'Apache': {
        '2.4.49': [
          { cve: 'CVE-2021-41773', severity: 'Critical', description: 'Path traversal vulnerability', cvss: 9.8 },
          { cve: 'CVE-2021-42013', severity: 'Critical', description: 'Path traversal vulnerability', cvss: 9.8 }
        ],
        '2.4.50': [
          { cve: 'CVE-2021-41773', severity: 'Critical', description: 'Path traversal vulnerability', cvss: 9.8 },
          { cve: 'CVE-2021-42013', severity: 'Critical', description: 'Path traversal vulnerability', cvss: 9.8 }
        ]
      },
      'WordPress': {
        '<5.8': [
          { cve: 'CVE-2021-29447', severity: 'High', description: 'Object injection vulnerability', cvss: 8.1 },
          { cve: 'CVE-2021-29450', severity: 'High', description: 'SSRF vulnerability', cvss: 8.1 }
        ],
        '<5.7': [
          { cve: 'CVE-2021-29447', severity: 'High', description: 'Object injection vulnerability', cvss: 8.1 },
          { cve: 'CVE-2021-29450', severity: 'High', description: 'SSRF vulnerability', cvss: 8.1 },
          { cve: 'CVE-2021-29451', severity: 'Medium', description: 'XSS vulnerability', cvss: 6.1 }
        ]
      },
      'PHP': {
        '<7.4': [
          { cve: 'CVE-2021-21708', severity: 'High', description: 'Use-after-free vulnerability', cvss: 8.1 },
          { cve: 'CVE-2021-21707', severity: 'High', description: 'Use-after-free vulnerability', cvss: 8.1 }
        ],
        '<8.0': [
          { cve: 'CVE-2021-21708', severity: 'High', description: 'Use-after-free vulnerability', cvss: 8.1 },
          { cve: 'CVE-2021-21707', severity: 'High', description: 'Use-after-free vulnerability', cvss: 8.1 }
        ]
      },
      'Nginx': {
        '<1.20': [
          { cve: 'CVE-2021-23017', severity: 'Medium', description: 'Integer overflow vulnerability', cvss: 5.3 }
        ]
      },
      'MySQL': {
        '<8.0': [
          { cve: 'CVE-2021-2166', severity: 'Medium', description: 'Privilege escalation vulnerability', cvss: 6.5 }
        ]
      },
      'OpenSSH': {
        '<8.5': [
          { cve: 'CVE-2021-28041', severity: 'Medium', description: 'Memory leak vulnerability', cvss: 5.5 }
        ]
      }
    };
    
    this.extractedVulns = [];
  }

  async extractVulnerabilities(intelligenceData) {
    console.log(chalk.bgBlue.white(`\n🔍 Basic Vuln Extractor - CVE Analysis`));
    
    const extractedVulns = [];
    
    // Extract vulnerabilities from technology stack
    for (const tech of intelligenceData.tech_stack) {
      const vulns = this.analyzeTechnology(tech);
      extractedVulns.push(...vulns);
    }
    
    // Extract vulnerabilities from services
    for (const [port, service] of Object.entries(intelligenceData.services)) {
      const vulns = this.analyzeService(service, port);
      extractedVulns.push(...vulns);
    }
    
    // Remove duplicates
    const uniqueVulns = this.removeDuplicateVulns(extractedVulns);
    
    // Sort by severity
    uniqueVulns.sort((a, b) => {
      const severityOrder = { 'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4 };
      return severityOrder[a.severity] - severityOrder[b.severity];
    });
    
    this.extractedVulns = uniqueVulns;
    
    console.log(chalk.green(`✅ Extracted ${uniqueVulns.length} unique vulnerabilities`));
    
    return uniqueVulns;
  }

  analyzeTechnology(tech) {
    const vulns = [];
    
    // Check each technology in the database
    for (const [software, versions] of Object.entries(this.vulnDatabase)) {
      if (tech.toLowerCase().includes(software.toLowerCase())) {
        // Extract version from technology string
        const versionMatch = tech.match(/(\d+\.\d+\.\d+)/);
        if (versionMatch) {
          const version = versionMatch[1];
          
          // Check if version is vulnerable
          for (const [vulnVersion, cves] of Object.entries(versions)) {
            if (this.isVersionVulnerable(version, vulnVersion)) {
              cves.forEach(cve => {
                vulns.push({
                  ...cve,
                  technology: software,
                  detected_version: version,
                  vulnerable_version: vulnVersion,
                  source: 'technology_stack'
                });
              });
            }
          }
        }
      }
    }
    
    return vulns;
  }

  analyzeService(service, port) {
    const vulns = [];
    
    // Analyze service string for vulnerabilities
    const serviceLower = service.toLowerCase();
    
    // Check for specific service vulnerabilities
    if (serviceLower.includes('apache')) {
      const versionMatch = service.match(/(\d+\.\d+\.\d+)/);
      if (versionMatch) {
        const version = versionMatch[1];
        const apacheVulns = this.vulnDatabase['Apache'];
        
        for (const [vulnVersion, cves] of Object.entries(apacheVulns)) {
          if (this.isVersionVulnerable(version, vulnVersion)) {
            cves.forEach(cve => {
              vulns.push({
                ...cve,
                technology: 'Apache',
                detected_version: version,
                vulnerable_version: vulnVersion,
                port: port,
                source: 'service_detection'
              });
            });
          }
        }
      }
    }
    
    // Check for database vulnerabilities
    if (serviceLower.includes('mysql') && port === '3306') {
      const versionMatch = service.match(/(\d+\.\d+\.\d+)/);
      if (versionMatch) {
        const version = versionMatch[1];
        const mysqlVulns = this.vulnDatabase['MySQL'];
        
        for (const [vulnVersion, cves] of Object.entries(mysqlVulns)) {
          if (this.isVersionVulnerable(version, vulnVersion)) {
            cves.forEach(cve => {
              vulns.push({
                ...cve,
                technology: 'MySQL',
                detected_version: version,
                vulnerable_version: vulnVersion,
                port: port,
                source: 'service_detection'
              });
            });
          }
        }
      }
    }
    
    // Check for SSH vulnerabilities
    if (serviceLower.includes('ssh') && port === '22') {
      const versionMatch = service.match(/(\d+\.\d+\.\d+)/);
      if (versionMatch) {
        const version = versionMatch[1];
        const sshVulns = this.vulnDatabase['OpenSSH'];
        
        for (const [vulnVersion, cves] of Object.entries(sshVulns)) {
          if (this.isVersionVulnerable(version, vulnVersion)) {
            cves.forEach(cve => {
              vulns.push({
                ...cve,
                technology: 'OpenSSH',
                detected_version: version,
                vulnerable_version: vulnVersion,
                port: port,
                source: 'service_detection'
              });
            });
          }
        }
      }
    }
    
    return vulns;
  }

  isVersionVulnerable(detectedVersion, vulnerableVersion) {
    if (vulnerableVersion.startsWith('<')) {
      const targetVersion = vulnerableVersion.substring(1);
      return this.compareVersions(detectedVersion, targetVersion);
    }
    
    return detectedVersion === vulnerableVersion;
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

  removeDuplicateVulns(vulns) {
    const seen = new Set();
    return vulns.filter(vuln => {
      const key = `${vuln.cve}-${vuln.technology}-${vuln.detected_version}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  async generateVulnReport(intelligenceData) {
    console.log(chalk.cyan(`\n📊 Generating Vulnerability Report...`));
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportDir = `./reports/${intelligenceData.target || 'vuln_extraction'}_${timestamp}`;
    
    try {
      await fs.mkdir(reportDir, { recursive: true });
      
      // Generate AI-powered vulnerability analysis
      const aiAnalysis = await this.generateAIVulnAnalysis();
      
      // Vulnerability extraction report
      const vulnReport = {
        target: intelligenceData.target,
        timestamp: new Date().toISOString(),
        total_vulnerabilities: this.extractedVulns.length,
        critical_count: this.extractedVulns.filter(v => v.severity === 'Critical').length,
        high_count: this.extractedVulns.filter(v => v.severity === 'High').length,
        medium_count: this.extractedVulns.filter(v => v.severity === 'Medium').length,
        low_count: this.extractedVulns.filter(v => v.severity === 'Low').length,
        vulnerabilities: this.extractedVulns,
        ai_analysis: aiAnalysis
      };
      
      await fs.writeFile(`${reportDir}/vuln_extraction.json`, JSON.stringify(vulnReport, null, 2));
      
      // Markdown vulnerability report
      const markdownReport = `# Vulnerability Extraction Report: ${intelligenceData.target}

## Executive Summary
- **Target**: ${intelligenceData.target}
- **Analysis Date**: ${new Date().toISOString()}
- **Total Vulnerabilities**: ${this.extractedVulns.length}
- **Critical**: ${vulnReport.critical_count}
- **High**: ${vulnReport.high_count}
- **Medium**: ${vulnReport.medium_count}
- **Low**: ${vulnReport.low_count}

## Critical Vulnerabilities
${this.extractedVulns.filter(v => v.severity === 'Critical').map(vuln => `
### ${vuln.cve}
- **Technology**: ${vuln.technology}
- **Detected Version**: ${vuln.detected_version}
- **Vulnerable Version**: ${vuln.vulnerable_version}
- **CVSS Score**: ${vuln.cvss}
- **Description**: ${vuln.description}
- **Source**: ${vuln.source}
- **Port**: ${vuln.port || 'N/A'}
`).join('')}

## High Severity Vulnerabilities
${this.extractedVulns.filter(v => v.severity === 'High').map(vuln => `
### ${vuln.cve}
- **Technology**: ${vuln.technology}
- **Detected Version**: ${vuln.detected_version}
- **Vulnerable Version**: ${vuln.vulnerable_version}
- **CVSS Score**: ${vuln.cvss}
- **Description**: ${vuln.description}
- **Source**: ${vuln.source}
- **Port**: ${vuln.port || 'N/A'}
`).join('')}

## Medium Severity Vulnerabilities
${this.extractedVulns.filter(v => v.severity === 'Medium').map(vuln => `
### ${vuln.cve}
- **Technology**: ${vuln.technology}
- **Detected Version**: ${vuln.detected_version}
- **Vulnerable Version**: ${vuln.vulnerable_version}
- **CVSS Score**: ${vuln.cvss}
- **Description**: ${vuln.description}
- **Source**: ${vuln.source}
- **Port**: ${vuln.port || 'N/A'}
`).join('')}

## Vulnerability Distribution by Technology
${this.getTechnologyDistribution()}

## AI-Powered Vulnerability Analysis
${aiAnalysis}
`;
      
      await fs.writeFile(`${reportDir}/vuln_report.md`, markdownReport);
      
      console.log(chalk.green(`\n📊 Vulnerability extraction reports generated in: ${reportDir}`));
      return reportDir;
    } catch (err) {
      console.log(chalk.red(`Vulnerability report generation failed: ${err.message}`));
    }
  }

  getTechnologyDistribution() {
    const distribution = {};
    
    this.extractedVulns.forEach(vuln => {
      if (!distribution[vuln.technology]) {
        distribution[vuln.technology] = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
      }
      
      distribution[vuln.technology].total++;
      distribution[vuln.technology][vuln.severity.toLowerCase()]++;
    });
    
    return Object.entries(distribution).map(([tech, counts]) => `
### ${tech}
- **Total**: ${counts.total}
- **Critical**: ${counts.critical}
- **High**: ${counts.high}
- **Medium**: ${counts.medium}
- **Low**: ${counts.low}
`).join('');
  }

  async generateAIVulnAnalysis() {
    const prompt = `Analyze the following extracted vulnerabilities and provide detailed insights:

Vulnerabilities: ${JSON.stringify(this.extractedVulns, null, 2)}

Please provide:
1. Vulnerability Risk Assessment (overall risk level and impact)
2. Exploitation Complexity Analysis (how easy are these to exploit)
3. Patch Priority Recommendations (which vulnerabilities to fix first)
4. Exploitation Scenarios (realistic attack scenarios)
5. Mitigation Strategies (how to protect against these vulnerabilities)
6. Compliance Impact (how these affect security compliance)

Format as markdown with clear sections and actionable recommendations.`;

    try {
      const aiResult = await mistral.chat.complete({
        model: "mistral-large-latest",
        messages: [{ role: "user", content: prompt }]
      });
      return aiResult.choices?.[0]?.message?.content;
    } catch (err) {
      return `AI vulnerability analysis failed: ${err.message}`;
    }
  }

  async processIntelligenceData(intelligenceData) {
    console.log(chalk.bgBlue.white(`\n🔍 Basic Vuln Extractor - Processing Intelligence Data`));
    
    // Extract vulnerabilities
    const vulns = await this.extractVulnerabilities(intelligenceData);
    
    // Generate report
    const reportDir = await this.generateVulnReport(intelligenceData);
    
    console.log(chalk.bgGreen.white(`\n✅ Basic Vuln Extractor completed!`));
    console.log(chalk.yellow(`📁 Reports saved to: ${reportDir}`));
    
    return {
      vulnerabilities: vulns,
      report_directory: reportDir
    };
  }
}

export { BasicVulnExtractor }; 