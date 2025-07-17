// recon/reconEngine.js
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import { askUser } from '../communicatetoUser.js';
import fs from 'fs/promises';
import path from 'path';
const execAsync = promisify(exec);

// Comprehensive tool map for complete reconnaissance
const toolMap = {
  'passive_recon': {
    'whois': { cmd: 'whois <target>', purpose: 'Domain registrant information and DNS history' },
    'theHarvester': { cmd: 'theHarvester -d <target> -b all', purpose: 'Email, hostnames, employee names from OSINT' },
    'subfinder': { cmd: 'subfinder -d <target>', purpose: 'Subdomain enumeration' },
    'amass': { cmd: 'amass enum -d <target>', purpose: 'Comprehensive subdomain discovery' },
    'dnsrecon': { cmd: 'dnsrecon -d <target>', purpose: 'DNS zone transfers, records, brute-force' },
    'crt.sh': { cmd: 'curl -s "https://crt.sh/?q=%.<target>&output=json"', purpose: 'SSL certificate transparency' },
    'shodan': { cmd: 'shodan host <target>', purpose: 'Shodan.io intelligence gathering' },
    'recon-ng': { cmd: 'recon-ng -w <target>', purpose: 'Modular OSINT framework' }
  },
  'active_recon': {
    'nmap_initial': { cmd: 'nmap -sS -p- <target>', purpose: 'Initial port scan - all ports' },
    'nmap_aggressive': { cmd: 'nmap -A -T4 <target>', purpose: 'Aggressive service detection' },
    'nmap_vuln': { cmd: 'nmap -sV --script vuln <target>', purpose: 'Vulnerability script scan' },
    'masscan': { cmd: 'masscan -p1-65535 --rate=1000 <target>', purpose: 'Ultra-fast port scanning' },
    'whatweb': { cmd: 'whatweb <target>', purpose: 'Web technology fingerprinting' },
    'nuclei': { cmd: 'nuclei -u <target>', purpose: 'CVE and vulnerability scanning' },
    'gobuster': { cmd: 'gobuster dir -u http://<target> -w /usr/share/wordlists/dirb/common.txt', purpose: 'Directory brute force' },
    'nikto': { cmd: 'nikto -h http://<target>', purpose: 'Web vulnerability scanner' },
    'sslscan': { cmd: 'sslscan <target>', purpose: 'SSL/TLS weakness analysis' },
    'enum4linux': { cmd: 'enum4linux <target>', purpose: 'SMB/NetBIOS enumeration' },
    'snmpwalk': { cmd: 'snmpwalk -v1 -c public <target>', purpose: 'SNMP discovery' },
    'ike-scan': { cmd: 'ike-scan <target>', purpose: 'IKE VPN fingerprinting' }
  },
  'web_enum': {
    'sqlmap': { cmd: 'sqlmap -u http://<target> --crawl=2', purpose: 'SQL injection testing' },
    'wapiti': { cmd: 'wapiti -u http://<target>', purpose: 'Web vulnerability scanner' },
    'xsstrike': { cmd: 'xsstrike -u http://<target>', purpose: 'XSS vulnerability scanner' },
    'hydra_web': { cmd: 'hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt <target> http-post-form', purpose: 'Web login brute force' }
  },
  'service_enum': {
    'smbclient': { cmd: 'smbclient -L //<target>', purpose: 'SMB service enumeration' },
    'nbtscan': { cmd: 'nbtscan <target>', purpose: 'NetBIOS name scanning' },
    'smtp_enum': { cmd: 'smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <target>', purpose: 'SMTP user enumeration' }
  }
};

// MCP Memory for storing intermediate results
let mcpMemory = {
  target: null,
  passive_results: {},
  active_results: {},
  discovered_services: [],
  open_ports: [],
  subdomains: [],
  vulnerabilities: [],
  timestamps: {},
  tool_outputs: {}
};

async function askMCPForReconPlan(target) {
  const prompt = `You are an advanced reconnaissance AI agent. Given target: ${target}, create a comprehensive reconnaissance plan. 
  
  Available tools: ${JSON.stringify(toolMap, null, 2)}
  
  Return a JSON object with this structure:
  {
    "passive_phase": [{"tool": "tool_name", "args": "command_args", "purpose": "description"}],
    "active_phase": [{"tool": "tool_name", "args": "command_args", "purpose": "description"}],
    "conditional_tools": {
      "if_web_detected": [{"tool": "tool_name", "args": "command_args", "purpose": "description"}],
      "if_smb_detected": [{"tool": "tool_name", "args": "command_args", "purpose": "description"}],
      "if_sql_detected": [{"tool": "tool_name", "args": "command_args", "purpose": "description"}]
    }
  }
  
  Focus on comprehensive intelligence gathering and vulnerability discovery.`;

  try {
    const aiResult = await mistral.chat.complete({
      model: "mistral-large-latest",
      messages: [{ role: "user", content: prompt }]
    });
    const content = aiResult.choices?.[0]?.message?.content;
    const match = content.match(/\{[\s\S]*\}/);
    if (match) {
      return JSON.parse(match[0]);
    }
    return JSON.parse(content);
  } catch (err) {
    console.log(chalk.red("\nAI recon plan generation failed: " + err.message));
    return generateDefaultPlan();
  }
}

function generateDefaultPlan() {
  return {
    passive_phase: [
      { tool: "whois", args: "<target>", purpose: "Domain information" },
      { tool: "theHarvester", args: "-d <target> -b all", purpose: "OSINT gathering" },
      { tool: "subfinder", args: "-d <target>", purpose: "Subdomain enumeration" }
    ],
    active_phase: [
      { tool: "nmap_initial", args: "<target>", purpose: "Port scanning" },
      { tool: "nmap_aggressive", args: "<target>", purpose: "Service detection" },
      { tool: "whatweb", args: "<target>", purpose: "Web fingerprinting" }
    ],
    conditional_tools: {
      if_web_detected: [
        { tool: "nikto", args: "-h http://<target>", purpose: "Web vulnerability scan" },
        { tool: "gobuster", args: "-u http://<target> -w /usr/share/wordlists/dirb/common.txt", purpose: "Directory enumeration" }
      ]
    }
  };
}

async function fillPlaceholders(args, tool) {
  let filledArgs = args;
  const placeholders = args.match(/<[^>]+>/g);
  if (placeholders) {
    for (const ph of placeholders) {
      if (ph === '<target>') {
        filledArgs = filledArgs.replace(ph, mcpMemory.target);
      } else {
        const value = await askUser(`Please provide a value for ${ph} in ${tool}:`);
        filledArgs = filledArgs.replace(ph, value);
      }
    }
  }
  return filledArgs;
}

async function runToolWithConfirmation(tool, args, purpose) {
  let finalArgs = await fillPlaceholders(args, tool);
  let cmd = `${tool} ${finalArgs}`;
  
  console.log(chalk.cyan(`\n🔧 Tool: ${tool}`));
  console.log(chalk.yellow(`📋 Purpose: ${purpose}`));
  console.log(chalk.green(`⚡ Command: ${cmd}`));
  
  const confirm = await askUser(`\nOptions: [r]un, [e]dit, [s]kip, [a]uto-run-all: `);
  
  if (confirm.toLowerCase() === 's') {
    return { status: 'skipped', output: `Skipped by user` };
  } else if (confirm.toLowerCase() === 'e') {
    finalArgs = await askUser(`Edit arguments for ${tool}:\nCurrent: ${finalArgs}\nNew: `);
    cmd = `${tool} ${finalArgs}`;
  } else if (confirm.toLowerCase() === 'a') {
    // Auto-run all remaining tools
    mcpMemory.auto_run = true;
  }
  
  if (confirm.toLowerCase() === 'r' || confirm.toLowerCase() === 'a' || mcpMemory.auto_run) {
    try {
      const startTime = Date.now();
      const { stdout, stderr } = await execAsync(cmd);
      const endTime = Date.now();
      
      mcpMemory.tool_outputs[tool] = {
        command: cmd,
        output: stdout,
        error: stderr,
        duration: endTime - startTime,
        timestamp: new Date().toISOString()
      };
      
      return { status: 'success', output: stdout, error: stderr };
    } catch (error) {
      mcpMemory.tool_outputs[tool] = {
        command: cmd,
        error: error.message,
        timestamp: new Date().toISOString()
      };
      return { status: 'error', output: error.message };
    }
  }
  
  return { status: 'skipped', output: 'Not executed' };
}

async function analyzeResultsWithMCP() {
  const prompt = `Analyze the following reconnaissance results and provide a comprehensive intelligence report:

Target: ${mcpMemory.target}
Tool Outputs: ${JSON.stringify(mcpMemory.tool_outputs, null, 2)}

Please provide:
1. Executive Summary
2. Discovered Assets (IPs, subdomains, services)
3. Open Ports and Services
4. Technology Stack
5. Identified Vulnerabilities
6. Attack Surface Analysis
7. Recommended Next Steps
8. Risk Assessment

Format the response in Markdown with clear sections.`;

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

async function generateReports() {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const reportDir = `./reports/${mcpMemory.target}_${timestamp}`;
  
  try {
    await fs.mkdir(reportDir, { recursive: true });
    
    // Generate JSON report
    const jsonReport = {
      target: mcpMemory.target,
      timestamp: new Date().toISOString(),
      tool_outputs: mcpMemory.tool_outputs,
      summary: {
        total_tools: Object.keys(mcpMemory.tool_outputs).length,
        successful_runs: Object.values(mcpMemory.tool_outputs).filter(t => !t.error).length,
        errors: Object.values(mcpMemory.tool_outputs).filter(t => t.error).length
      }
    };
    
    await fs.writeFile(`${reportDir}/recon_data.json`, JSON.stringify(jsonReport, null, 2));
    
    // Generate Markdown report
    const markdownReport = `# Reconnaissance Report: ${mcpMemory.target}

## Executive Summary
Target: ${mcpMemory.target}
Scan Date: ${new Date().toISOString()}
Total Tools Executed: ${Object.keys(mcpMemory.tool_outputs).length}

## Tool Execution Summary
${Object.entries(mcpMemory.tool_outputs).map(([tool, data]) => `
### ${tool}
- Command: \`${data.command}\`
- Status: ${data.error ? '❌ Error' : '✅ Success'}
- Duration: ${data.duration ? `${data.duration}ms` : 'N/A'}
- Timestamp: ${data.timestamp}
`).join('')}

## Raw Outputs
${Object.entries(mcpMemory.tool_outputs).map(([tool, data]) => `
### ${tool} Output
\`\`\`
${data.output || data.error || 'No output'}
\`\`\`
`).join('')}
`;
    
    await fs.writeFile(`${reportDir}/recon_report.md`, markdownReport);
    
    console.log(chalk.green(`\n📊 Reports generated in: ${reportDir}`));
    return reportDir;
  } catch (err) {
    console.log(chalk.red(`Report generation failed: ${err.message}`));
  }
}

export async function reconEngine(target) {
  console.log(chalk.bgBlue.white(`\n🎯 Starting Comprehensive Reconnaissance on: ${target}`));
  console.log(chalk.yellow(`📋 Objective: Complete intelligence gathering and vulnerability assessment`));
  
  mcpMemory.target = target;
  mcpMemory.auto_run = false;
  
  // Get AI-driven recon plan
  console.log(chalk.bgCyan.black(`\n🤖 Generating AI-driven reconnaissance plan...`));
  const reconPlan = await askMCPForReconPlan(target);
  
  // Phase 1: Passive Reconnaissance
  console.log(chalk.bgGreen.black(`\n🔍 PHASE 1: Passive Reconnaissance`));
  for (const tool of reconPlan.passive_phase || []) {
    const result = await runToolWithConfirmation(tool.tool, tool.args, tool.purpose);
    console.log(chalk.cyan(`Result: ${result.status}`));
    if (result.output) console.log(result.output.substring(0, 200) + '...');
  }
  
  // Phase 2: Active Reconnaissance
  console.log(chalk.bgYellow.black(`\n🚀 PHASE 2: Active Reconnaissance`));
  for (const tool of reconPlan.active_phase || []) {
    const result = await runToolWithConfirmation(tool.tool, tool.args, tool.purpose);
    console.log(chalk.cyan(`Result: ${result.status}`));
    if (result.output) console.log(result.output.substring(0, 200) + '...');
  }
  
  // Phase 3: Conditional Tools (based on discovered services)
  console.log(chalk.bgMagenta.black(`\n⚡ PHASE 3: Conditional Enumeration`));
  for (const [condition, tools] of Object.entries(reconPlan.conditional_tools || {})) {
    console.log(chalk.cyan(`\nCondition: ${condition}`));
    for (const tool of tools) {
      const result = await runToolWithConfirmation(tool.tool, tool.args, tool.purpose);
      console.log(chalk.cyan(`Result: ${result.status}`));
    }
  }
  
  // Generate comprehensive analysis
  console.log(chalk.bgBlue.black(`\n🧠 AI Analysis and Intelligence Correlation`));
  const aiAnalysis = await analyzeResultsWithMCP();
  console.log(chalk.bgMagenta.white(`\nAI Intelligence Report:`));
  console.log(aiAnalysis);
  
  // Generate reports
  console.log(chalk.bgGreen.black(`\n📊 Generating Reports`));
  const reportDir = await generateReports();
  
  console.log(chalk.bgGreen.white(`\n✅ Comprehensive reconnaissance completed!`));
  console.log(chalk.yellow(`📁 Reports saved to: ${reportDir}`));
}

export async function runChunkedRecon(target) {
  await reconEngine(target);
}
