// Contextual Intelligence Engine - Advanced Analysis & Correlation
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import fs from 'fs/promises';

class ContextualIntelligenceEngine {
  constructor() {
    this.context = {
      target: null,
      intelligence_data: null,
      contextual_findings: [],
      attack_paths: [],
      business_impact: {},
      compliance_issues: [],
      remediation_priorities: []
    };
  }

  async processIntelligenceData(intelligenceData) {
    console.log(chalk.bgBlue.white(`\n🧠 Contextual Intelligence Engine - Deep Analysis`));
    
    this.context.target = intelligenceData.target;
    this.context.intelligence_data = intelligenceData;
    
    // Perform contextual analysis
    await this.analyzeAttackPaths();
    await this.assessBusinessImpact();
    await this.checkComplianceIssues();
    await this.prioritizeRemediation();
    await this.generateContextualReport();
    
    return this.context;
  }

  async analyzeAttackPaths() {
    console.log(chalk.cyan(`\n🔍 Analyzing Potential Attack Paths...`));
    
    const data = this.context.intelligence_data;
    const attackPaths = [];
    
    // Web application attack paths
    if (data.open_ports.includes(80) || data.open_ports.includes(443)) {
      if (data.tech_stack.some(tech => tech.includes('WordPress'))) {
        attackPaths.push({
          type: 'Web Application',
          vector: 'WordPress Exploitation',
          description: 'WordPress CMS detected - potential for plugin vulnerabilities, weak credentials, and outdated versions',
          severity: 'High',
          prerequisites: ['Web access', 'WordPress installation'],
          potential_payloads: ['SQL injection', 'XSS', 'File upload', 'Authentication bypass']
        });
      }
      
      if (data.tech_stack.some(tech => tech.includes('PHP'))) {
        attackPaths.push({
          type: 'Web Application',
          vector: 'PHP Exploitation',
          description: 'PHP detected - potential for code injection, file inclusion, and command execution',
          severity: 'High',
          prerequisites: ['Web access', 'PHP execution'],
          potential_payloads: ['PHP code injection', 'LFI/RFI', 'Command injection']
        });
      }
    }
    
    // Database attack paths
    if (data.open_ports.includes(3306)) {
      attackPaths.push({
        type: 'Database',
        vector: 'MySQL Exploitation',
        description: 'MySQL database detected - potential for SQL injection, weak credentials, and privilege escalation',
        severity: 'High',
        prerequisites: ['Database access', 'Valid credentials'],
        potential_payloads: ['SQL injection', 'Privilege escalation', 'Data exfiltration']
      });
    }
    
    if (data.open_ports.includes(1433)) {
      attackPaths.push({
        type: 'Database',
        vector: 'MSSQL Exploitation',
        description: 'Microsoft SQL Server detected - potential for SQL injection and xp_cmdshell execution',
        severity: 'High',
        prerequisites: ['Database access', 'Valid credentials'],
        potential_payloads: ['SQL injection', 'xp_cmdshell', 'Data exfiltration']
      });
    }
    
    // Remote access attack paths
    if (data.open_ports.includes(22)) {
      attackPaths.push({
        type: 'Remote Access',
        vector: 'SSH Exploitation',
        description: 'SSH service detected - potential for brute force, key-based attacks, and weak configurations',
        severity: 'Medium',
        prerequisites: ['SSH access', 'Valid credentials or keys'],
        potential_payloads: ['Brute force', 'Key-based attacks', 'Configuration weaknesses']
      });
    }
    
    if (data.open_ports.includes(3389)) {
      attackPaths.push({
        type: 'Remote Access',
        vector: 'RDP Exploitation',
        description: 'Remote Desktop Protocol detected - potential for brute force and credential attacks',
        severity: 'High',
        prerequisites: ['RDP access', 'Valid credentials'],
        potential_payloads: ['Brute force', 'Credential stuffing', 'BlueKeep exploit']
      });
    }
    
    this.context.attack_paths = attackPaths;
    console.log(chalk.green(`✅ Identified ${attackPaths.length} potential attack paths`));
  }

  async assessBusinessImpact() {
    console.log(chalk.cyan(`\n💼 Assessing Business Impact...`));
    
    const data = this.context.intelligence_data;
    const businessImpact = {
      data_breach_risk: 'Low',
      service_disruption_risk: 'Low',
      compliance_risk: 'Low',
      reputation_risk: 'Low',
      financial_impact: 'Low',
      details: []
    };
    
    // Assess data breach risk
    if (data.open_ports.includes(3306) || data.open_ports.includes(1433)) {
      businessImpact.data_breach_risk = 'High';
      businessImpact.details.push('Database services exposed - potential for data exfiltration');
    }
    
    if (data.possible_vulns.length > 5) {
      businessImpact.data_breach_risk = 'Medium';
      businessImpact.details.push('Multiple vulnerabilities detected - increased attack surface');
    }
    
    // Assess service disruption risk
    if (data.open_ports.includes(80) || data.open_ports.includes(443)) {
      businessImpact.service_disruption_risk = 'Medium';
      businessImpact.details.push('Web services exposed - potential for DDoS or defacement');
    }
    
    // Assess compliance risk
    if (data.ssl_info && Object.keys(data.ssl_info).length > 0) {
      if (data.risk_matrix.medium.some(risk => risk.includes('Weak cipher'))) {
        businessImpact.compliance_risk = 'Medium';
        businessImpact.details.push('Weak SSL/TLS configuration - potential compliance violation');
      }
    }
    
    // Assess reputation risk
    if (data.tech_stack.some(tech => tech.includes('WordPress'))) {
      businessImpact.reputation_risk = 'Medium';
      businessImpact.details.push('WordPress CMS - potential for public defacement');
    }
    
    // Calculate financial impact
    const riskFactors = [
      businessImpact.data_breach_risk === 'High' ? 3 : businessImpact.data_breach_risk === 'Medium' ? 2 : 1,
      businessImpact.service_disruption_risk === 'High' ? 3 : businessImpact.service_disruption_risk === 'Medium' ? 2 : 1,
      businessImpact.compliance_risk === 'High' ? 3 : businessImpact.compliance_risk === 'Medium' ? 2 : 1,
      businessImpact.reputation_risk === 'High' ? 3 : businessImpact.reputation_risk === 'Medium' ? 2 : 1
    ];
    
    const totalRisk = riskFactors.reduce((sum, factor) => sum + factor, 0);
    if (totalRisk >= 10) businessImpact.financial_impact = 'High';
    else if (totalRisk >= 7) businessImpact.financial_impact = 'Medium';
    
    this.context.business_impact = businessImpact;
    console.log(chalk.green(`✅ Business impact assessment completed`));
  }

  async checkComplianceIssues() {
    console.log(chalk.cyan(`\n📋 Checking Compliance Issues...`));
    
    const data = this.context.intelligence_data;
    const complianceIssues = [];
    
    // PCI DSS compliance
    if (data.open_ports.includes(3306) || data.open_ports.includes(1433)) {
      complianceIssues.push({
        standard: 'PCI DSS',
        requirement: 'Requirement 1: Install and maintain a firewall',
        issue: 'Database services directly exposed to internet',
        severity: 'High',
        remediation: 'Implement firewall rules to restrict database access'
      });
    }
    
    // GDPR compliance
    if (data.possible_vulns.length > 0) {
      complianceIssues.push({
        standard: 'GDPR',
        requirement: 'Article 32: Security of processing',
        issue: 'Multiple vulnerabilities detected in data processing systems',
        severity: 'Medium',
        remediation: 'Implement security measures to protect personal data'
      });
    }
    
    // SOX compliance
    if (data.open_ports.includes(22) || data.open_ports.includes(3389)) {
      complianceIssues.push({
        standard: 'SOX',
        requirement: 'Section 404: Internal controls',
        issue: 'Remote access services exposed without proper controls',
        severity: 'Medium',
        remediation: 'Implement access controls and monitoring for remote access'
      });
    }
    
    // SSL/TLS compliance
    if (data.ssl_info && data.risk_matrix.medium.some(risk => risk.includes('Weak cipher'))) {
      complianceIssues.push({
        standard: 'TLS 1.2+',
        requirement: 'Strong encryption requirements',
        issue: 'Weak SSL/TLS cipher suites detected',
        severity: 'Medium',
        remediation: 'Disable weak cipher suites and enforce TLS 1.2+'
      });
    }
    
    this.context.compliance_issues = complianceIssues;
    console.log(chalk.green(`✅ Compliance check completed - ${complianceIssues.length} issues found`));
  }

  async prioritizeRemediation() {
    console.log(chalk.cyan(`\n🎯 Prioritizing Remediation Actions...`));
    
    const data = this.context.intelligence_data;
    const remediationPriorities = [];
    
    // Critical vulnerabilities (immediate action required)
    data.possible_vulns.forEach(vuln => {
      if (vuln.severity === 'High') {
        remediationPriorities.push({
          priority: 'Critical',
          action: `Patch ${vuln.service} to address ${vuln.cve}`,
          timeframe: 'Immediate (24-48 hours)',
          effort: 'Low',
          impact: 'High',
          description: vuln.description
        });
      }
    });
    
    // High-risk services
    if (data.open_ports.includes(3389)) {
      remediationPriorities.push({
        priority: 'High',
        action: 'Secure RDP access',
        timeframe: '1 week',
        effort: 'Medium',
        impact: 'High',
        description: 'Implement VPN, MFA, and access controls for RDP'
      });
    }
    
    if (data.open_ports.includes(3306) || data.open_ports.includes(1433)) {
      remediationPriorities.push({
        priority: 'High',
        action: 'Secure database access',
        timeframe: '1 week',
        effort: 'Medium',
        impact: 'High',
        description: 'Implement firewall rules and secure database configuration'
      });
    }
    
    // Medium-risk issues
    if (data.tech_stack.some(tech => tech.includes('WordPress'))) {
      remediationPriorities.push({
        priority: 'Medium',
        action: 'Update WordPress and plugins',
        timeframe: '2 weeks',
        effort: 'Low',
        impact: 'Medium',
        description: 'Keep WordPress core and plugins updated to latest versions'
      });
    }
    
    // SSL/TLS issues
    if (data.risk_matrix.medium.some(risk => risk.includes('Weak cipher'))) {
      remediationPriorities.push({
        priority: 'Medium',
        action: 'Update SSL/TLS configuration',
        timeframe: '2 weeks',
        effort: 'Low',
        impact: 'Medium',
        description: 'Disable weak cipher suites and enforce strong encryption'
      });
    }
    
    // Sort by priority
    const priorityOrder = { 'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4 };
    remediationPriorities.sort((a, b) => priorityOrder[a.priority] - priorityOrder[b.priority]);
    
    this.context.remediation_priorities = remediationPriorities;
    console.log(chalk.green(`✅ Remediation priorities established`));
  }

  async generateContextualReport() {
    console.log(chalk.cyan(`\n📊 Generating Contextual Intelligence Report...`));
    
    const data = this.context.intelligence_data;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportDir = `./reports/${data.target || 'contextual'}_${timestamp}`;
    
    try {
      await fs.mkdir(reportDir, { recursive: true });
      
      // Generate contextual analysis with AI
      const aiAnalysis = await this.generateAIContextualAnalysis();
      
      // Contextual intelligence report
      const contextualReport = {
        target: data.target,
        timestamp: new Date().toISOString(),
        intelligence_data: data,
        attack_paths: this.context.attack_paths,
        business_impact: this.context.business_impact,
        compliance_issues: this.context.compliance_issues,
        remediation_priorities: this.context.remediation_priorities,
        ai_analysis: aiAnalysis
      };
      
      await fs.writeFile(`${reportDir}/contextual_intelligence.json`, JSON.stringify(contextualReport, null, 2));
      
      // Markdown contextual report
      const markdownReport = `# Contextual Intelligence Report: ${data.target}

## Executive Summary
- **Target**: ${data.target}
- **Analysis Date**: ${new Date().toISOString()}
- **Overall Risk Level**: ${this.getOverallRiskLevel()}
- **Business Impact**: ${this.context.business_impact.financial_impact}

## Attack Path Analysis

### Critical Attack Paths
${this.context.attack_paths.filter(path => path.severity === 'High').map(path => `
#### ${path.vector}
- **Type**: ${path.type}
- **Description**: ${path.description}
- **Prerequisites**: ${path.prerequisites.join(', ')}
- **Potential Payloads**: ${path.potential_payloads.join(', ')}
`).join('')}

### Medium Risk Attack Paths
${this.context.attack_paths.filter(path => path.severity === 'Medium').map(path => `
#### ${path.vector}
- **Type**: ${path.type}
- **Description**: ${path.description}
- **Prerequisites**: ${path.prerequisites.join(', ')}
- **Potential Payloads**: ${path.potential_payloads.join(', ')}
`).join('')}

## Business Impact Assessment

### Risk Categories
- **Data Breach Risk**: ${this.context.business_impact.data_breach_risk}
- **Service Disruption Risk**: ${this.context.business_impact.service_disruption_risk}
- **Compliance Risk**: ${this.context.business_impact.compliance_risk}
- **Reputation Risk**: ${this.context.business_impact.reputation_risk}
- **Financial Impact**: ${this.context.business_impact.financial_impact}

### Impact Details
${this.context.business_impact.details.map(detail => `- ${detail}`).join('\n')}

## Compliance Issues

${this.context.compliance_issues.map(issue => `
### ${issue.standard} - ${issue.requirement}
- **Issue**: ${issue.issue}
- **Severity**: ${issue.severity}
- **Remediation**: ${issue.remediation}
`).join('')}

## Remediation Priorities

### Critical (Immediate Action Required)
${this.context.remediation_priorities.filter(item => item.priority === 'Critical').map(item => `
- **${item.action}**
  - Timeframe: ${item.timeframe}
  - Effort: ${item.effort}
  - Impact: ${item.impact}
  - Description: ${item.description}
`).join('')}

### High Priority (1 Week)
${this.context.remediation_priorities.filter(item => item.priority === 'High').map(item => `
- **${item.action}**
  - Timeframe: ${item.timeframe}
  - Effort: ${item.effort}
  - Impact: ${item.impact}
  - Description: ${item.description}
`).join('')}

### Medium Priority (2 Weeks)
${this.context.remediation_priorities.filter(item => item.priority === 'Medium').map(item => `
- **${item.action}**
  - Timeframe: ${item.timeframe}
  - Effort: ${item.effort}
  - Impact: ${item.impact}
  - Description: ${item.description}
`).join('')}

## AI-Powered Contextual Analysis
${aiAnalysis}
`;
      
      await fs.writeFile(`${reportDir}/contextual_report.md`, markdownReport);
      
      console.log(chalk.green(`\n📊 Contextual intelligence reports generated in: ${reportDir}`));
      return reportDir;
    } catch (err) {
      console.log(chalk.red(`Contextual report generation failed: ${err.message}`));
    }
  }

  async generateAIContextualAnalysis() {
    const data = this.context.intelligence_data;
    
    const prompt = `Provide a comprehensive contextual analysis of the following security intelligence:

Target: ${data.target}
Attack Paths: ${JSON.stringify(this.context.attack_paths)}
Business Impact: ${JSON.stringify(this.context.business_impact)}
Compliance Issues: ${JSON.stringify(this.context.compliance_issues)}
Remediation Priorities: ${JSON.stringify(this.context.remediation_priorities)}

Please provide:
1. Strategic Risk Assessment (how these findings impact business objectives)
2. Threat Actor Analysis (what types of attackers would target this infrastructure)
3. Attack Scenario Modeling (realistic attack scenarios based on findings)
4. Defense-in-Depth Recommendations (layered security approach)
5. Incident Response Preparation (what to do if these vulnerabilities are exploited)
6. Long-term Security Strategy (3-6 month roadmap)

Format as markdown with clear sections and actionable insights.`;

    try {
      const aiResult = await mistral.chat.complete({
        model: "mistral-large-latest",
        messages: [{ role: "user", content: prompt }]
      });
      return aiResult.choices?.[0]?.message?.content;
    } catch (err) {
      return `AI contextual analysis failed: ${err.message}`;
    }
  }

  getOverallRiskLevel() {
    const criticalCount = this.context.remediation_priorities.filter(item => item.priority === 'Critical').length;
    const highCount = this.context.remediation_priorities.filter(item => item.priority === 'High').length;
    
    if (criticalCount > 0) return 'Critical';
    if (highCount > 2) return 'High';
    if (highCount > 0 || this.context.compliance_issues.length > 2) return 'Medium';
    return 'Low';
  }
}

export { ContextualIntelligenceEngine }; 