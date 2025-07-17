// recon/reconEngine.js
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

// Tool map: categories to tool commands
const toolMap = {
  'network_scan': ['nmap', 'arp-scan', 'netdiscover', 'masscan'],
  'port_scan': ['nmap', 'masscan', 'rustscan'],
  'web_scan': ['nikto', 'dirb', 'gobuster', 'ffuf', 'wfuzz'],
  'vulnerability_scan': ['nmap', 'nikto', 'sqlmap', 'xsstrike'],
  'password_crack': ['john', 'hashcat', 'hydra', 'medusa'],
  'file_analysis': ['file', 'strings', 'hexdump', 'binwalk'],
  'process_analysis': ['ps', 'top', 'htop', 'lsof', 'netstat'],
  'system_info': ['uname', 'lscpu', 'free', 'df', 'uptime'],
  'text_processing': ['grep', 'sed', 'awk', 'cut', 'sort', 'uniq'],
  'file_operations': ['ls', 'find', 'locate', 'which', 'whereis']
};

async function askMCPWhichCategoriesAndTools(target) {
  const prompt = `You are an advanced recon AI. Given the target: ${target}, select the most effective categories and tools from this map: ${JSON.stringify(toolMap, null, 2)}.\nReturn a JSON object with categories as keys and arrays of tool commands as values, e.g. {\"network_scan\": [\"nmap\", \"arp-scan\"]}`;
  try {
    const aiResult = await mistral.chat.complete({
      model: "mistral-large-latest",
      messages: [
        { role: "user", content: prompt }
      ]
    });
    const content = aiResult.choices?.[0]?.message?.content;
    // Try to extract JSON object from the response
    const match = content.match(/\{[\s\S]*\}/);
    if (match) {
      return JSON.parse(match[0]);
    }
    // fallback: try to parse whole content
    return JSON.parse(content);
  } catch (err) {
    console.log(chalk.red("\nAI tool selection failed: " + err.message));
    // fallback: run all tools in all categories
    return toolMap;
  }
}

async function runToolCommand(tool, target) {
  // Build a basic command for each tool (customize as needed)
  let cmd = tool;
  // Add target if the tool expects it
  if ([
    'nmap', 'arp-scan', 'netdiscover', 'masscan', 'nikto', 'dirb', 'gobuster', 'ffuf', 'wfuzz', 'sqlmap', 'xsstrike', 'whois', 'sslscan', 'whatweb', 'amass'
  ].includes(tool)) {
    cmd += ` ${target}`;
  }
  try {
    const { stdout } = await execAsync(cmd);
    return `\n[${tool}]\n${stdout}`;
  } catch (error) {
    return `\n[${tool} ERROR] ${error.message}`;
  }
}

export async function reconEngine(target) {
  console.log(chalk.bgBlue.white(`\n🤖 Asking MCP which categories and tools to run for: ${target}`));
  const selected = await askMCPWhichCategoriesAndTools(target);
  console.log(chalk.bgCyan.black("\nMCP selected tools:"));
  Object.entries(selected).forEach(([cat, tools]) => {
    console.log(chalk.yellow(cat) + ': ' + tools.map(t => chalk.green(t)).join(', '));
  });

  let results = [];
  for (const [category, tools] of Object.entries(selected)) {
    results.push(chalk.bold(`\n=== ${category} ===`));
    for (const tool of tools) {
      results.push(await runToolCommand(tool, target));
    }
  }

  // Print and summarize results
  const allResults = results.filter(Boolean).join('\n');
  console.log(chalk.bgGreen.black("\nRecon Results:"));
  console.log(allResults);

  // AI summary with Mistral
  const aiPrompt = `Summarize and analyze the following recon results for target ${target}. Provide actionable insights and next steps.\n${allResults}`;
  try {
    const aiResult = await mistral.chat.complete({
      model: "mistral-large-latest",
      messages: [
        { role: "user", content: aiPrompt }
      ]
    });
    console.log(chalk.bgMagenta.white("\nAI Summary:"));
    console.log(aiResult.choices?.[0]?.message?.content || JSON.stringify(aiResult));
  } catch (err) {
    console.log(chalk.red("\nAI summary failed: " + err.message));
  }
}

export async function runChunkedRecon(target) {
  await reconEngine(target);
}
