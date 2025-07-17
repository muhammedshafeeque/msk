// recon/reconEngine.js
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import { askUser } from '../communicatetoUser.js';
import fs from 'fs/promises';
import path from 'path';
import { FastIntelligenceEngine } from './IntelligenceEngine.js';
import { ContextualIntelligenceEngine } from './ContextualEngine.js';
import { BasicVulnExtractor } from './VulnExtractor.js';
import { ExploitFinder } from './ExploitFinder.js';
const execAsync = promisify(exec);

// Check for common tool installations
async function checkToolAvailability() {
  const commonTools = ['nmap', 'masscan', 'whatweb', 'gobuster', 'nikto', 'enum4linux', 'snmpwalk', 'ike-scan'];
  const missingTools = [];
  
  for (const tool of commonTools) {
    try {
      await execAsync(`which ${tool}`);
    } catch (error) {
      missingTools.push(tool);
    }
  }
  
  if (missingTools.length > 0) {
    console.log(chalk.yellow(`\n⚠️  Missing tools: ${missingTools.join(', ')}`));
    console.log(chalk.cyan(`💡 Install missing tools with: sudo apt install ${missingTools.join(' ')}`));
  }
  
  return missingTools;
}

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
    'masscan': { cmd: 'sudo masscan -p1-65535 --rate=1000 <target>', purpose: 'Ultra-fast port scanning' },
    'whatweb': { cmd: 'whatweb <target>', purpose: 'Web technology fingerprinting' },
    'nuclei': { cmd: 'nuclei -u http://<target>', purpose: 'CVE and vulnerability scanning' },
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
  // Determine if target is IP or domain
  const isIP = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(target);
  
  const prompt = `You are an advanced reconnaissance AI agent. Given target: ${target} (${isIP ? 'IP address' : 'domain'}), create a comprehensive reconnaissance plan. 
  
  Available tools: ${JSON.stringify(toolMap, null, 2)}
  
  IMPORTANT: For IP addresses, skip domain-specific tools like subfinder, amass, dnsrecon, crt.sh, theHarvester. Focus on network scanning and service enumeration.
  
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
  
  Focus on comprehensive intelligence gathering and vulnerability discovery. For IP targets, prioritize network scanning and service discovery.`;

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
    return generateDefaultPlan(target);
  }
}

function generateDefaultPlan(target) {
  const isIP = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(target);
  
  if (isIP) {
    // IP-specific plan - focus on network scanning and service discovery
    return {
      passive_phase: [
        { tool: "whois", args: "<target>", purpose: "IP information" }
      ],
      active_phase: [
        { tool: "nmap_initial", args: "<target>", purpose: "Port scanning" },
        { tool: "whatweb", args: "<target>", purpose: "Web fingerprinting" },
        { tool: "enum4linux", args: "<target>", purpose: "SMB enumeration" },
        { tool: "ike-scan", args: "<target>", purpose: "IKE VPN fingerprinting" }
      ],
      conditional_tools: {
        if_web_detected: [
          { tool: "gobuster", args: "-u http://<target> -w /usr/share/wordlists/dirb/common.txt", purpose: "Directory enumeration" }
        ],
        if_smb_detected: [
          { tool: "enum4linux", args: "<target>", purpose: "SMB enumeration" }
        ]
      }
    };
  } else {
    // Domain-specific plan
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
  
  // Get the actual command from toolMap
  let actualTool = tool;
  let cmd = finalArgs;
  
  // Check if this is a mapped tool (like nmap_initial, nmap_aggressive, etc.)
  for (const category of Object.values(toolMap)) {
    for (const [toolName, toolInfo] of Object.entries(category)) {
      if (toolName === tool) {
        // Extract the actual command from the tool info
        const toolCmd = toolInfo.cmd;
        const filledCmd = await fillPlaceholders(toolCmd, toolName);
        cmd = filledCmd;
        // Extract the actual tool name (first word of the command)
        actualTool = filledCmd.split(' ')[0];
        break;
      }
    }
  }
  
  // If not found in toolMap, use the original logic
  if (cmd === finalArgs) {
    if (!finalArgs.startsWith(tool)) {
      cmd = `${tool} ${finalArgs}`;
    }
  }
  
  console.log(chalk.cyan(`\n🔧 Tool: ${tool}`));
  console.log(chalk.yellow(`📋 Purpose: ${purpose}`));
  console.log(chalk.green(`⚡ Command: ${cmd}`));
  
  // Check if tool is available
  try {
    await execAsync(`which ${actualTool}`);
  } catch (error) {
    console.log(chalk.red(`❌ Tool ${actualTool} not found. Skipping...`));
    return { status: 'skipped', output: `Tool ${actualTool} not installed` };
  }
  
  // Special check for Shodan
  if (actualTool === 'shodan') {
    try {
      await execAsync('shodan info');
    } catch (error) {
      console.log(chalk.red(`❌ Shodan not configured. Run 'shodan init <api_key>' first. Skipping...`));
      return { status: 'skipped', output: 'Shodan API key not configured' };
    }
  }
  
  // Only ask for confirmation if auto_run is not enabled
  if (!mcpMemory.auto_run) {
    const confirm = await askUser(`\nOptions: [r]un, [e]dit, [s]kip, [a]uto-run-all: `);
    
    if (confirm.toLowerCase() === 's') {
      return { status: 'skipped', output: `Skipped by user` };
    } else if (confirm.toLowerCase() === 'e') {
      finalArgs = await askUser(`Edit arguments for ${tool}:\nCurrent: ${finalArgs}\nNew: `);
      cmd = finalArgs.startsWith(tool) ? finalArgs : `${tool} ${finalArgs}`;
    } else if (confirm.toLowerCase() === 'a') {
      // Auto-run all remaining tools
      mcpMemory.auto_run = true;
    } else if (confirm.toLowerCase() !== 'r') {
      return { status: 'skipped', output: 'Not executed' };
    }
  }
  
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
    
    console.log(chalk.green(`✅ ${tool} completed successfully`));
    return { status: 'success', output: stdout, error: stderr };
  } catch (error) {
    mcpMemory.tool_outputs[tool] = {
      command: cmd,
      error: error.message,
      timestamp: new Date().toISOString()
    };
    
    console.log(chalk.red(`❌ ${tool} failed: ${error.message}`));
    
    // Handle errors based on auto_skip_errors setting
    if (mcpMemory.auto_skip_errors) {
      console.log(chalk.yellow(`⏭️  Auto-skipping failed tool due to smart mode`));
      return { status: 'error', output: error.message };
    }
    
    // Ask user what to do on error
    const errorAction = await askUser(`\nTool failed. Options: [s]kip, [r]etry, [e]dit, [a]uto-skip-errors: `);
    
    if (errorAction.toLowerCase() === 'r') {
      return await runToolWithConfirmation(tool, args, purpose);
    } else if (errorAction.toLowerCase() === 'e') {
      const newArgs = await askUser(`Edit command for ${tool}:\nCurrent: ${cmd}\nNew: `);
      return await runToolWithConfirmation(tool, newArgs, purpose);
    } else if (errorAction.toLowerCase() === 'a') {
      mcpMemory.auto_skip_errors = true;
    }
    
    return { status: 'error', output: error.message };
  }
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
  mcpMemory.auto_skip_errors = false;
  
  // Check tool availability first
  console.log(chalk.cyan(`\n🔍 Checking tool availability...`));
  await checkToolAvailability();
  
  // Ask user for execution mode
  console.log(chalk.cyan(`\n🚀 Execution Mode Selection:`));
  const mode = await askUser(`Choose mode: [i]nteractive (confirm each tool), [a]uto-run-all, [s]mart (auto-run, ask on errors): `);
  
  if (mode.toLowerCase() === 'a') {
    mcpMemory.auto_run = true;
    console.log(chalk.green(`✅ Auto-run mode enabled - all tools will run automatically`));
  } else if (mode.toLowerCase() === 's') {
    mcpMemory.auto_run = true;
    mcpMemory.auto_skip_errors = true;
    console.log(chalk.green(`✅ Smart mode enabled - auto-run with error handling`));
  } else {
    console.log(chalk.yellow(`✅ Interactive mode - you'll confirm each tool execution`));
  }
  
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
  
  // Phase 4: Fast Intelligence Engine Processing
  console.log(chalk.bgBlue.black(`\n🧠 PHASE 4: Fast Intelligence Engine Processing`));
  const intelligenceEngine = new FastIntelligenceEngine();
  const intelligenceData = await intelligenceEngine.processReconResults(mcpMemory.tool_outputs);
  
  // Store intelligence data in MCP memory for chaining
  mcpMemory.intelligence_data = intelligenceData;
  
  // Phase 5: Contextual Intelligence Engine Processing
  console.log(chalk.bgBlue.black(`\n🧠 PHASE 5: Contextual Intelligence Engine Processing`));
  const contextualEngine = new ContextualIntelligenceEngine();
  const contextualData = await contextualEngine.processIntelligenceData(intelligenceData);
  
  // Store contextual data in MCP memory for chaining
  mcpMemory.contextual_data = contextualData;
  
  // Phase 6: Basic Vuln Extractor Processing
  console.log(chalk.bgBlue.black(`\n🔍 PHASE 6: Basic Vuln Extractor Processing`));
  const vulnExtractor = new BasicVulnExtractor();
  const vulnData = await vulnExtractor.processIntelligenceData(intelligenceData);
  
  // Store vulnerability data in MCP memory for chaining
  mcpMemory.vuln_data = vulnData;
  
  // Phase 7: Exploit Finder & Fetcher Processing
  console.log(chalk.bgBlue.black(`\n💥 PHASE 7: Exploit Finder & Fetcher Processing`));
  const exploitFinder = new ExploitFinder();
  const exploitData = await exploitFinder.processVulnData(vulnData);
  
  // Store exploit data in MCP memory for chaining
  mcpMemory.exploit_data = exploitData;
  
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
