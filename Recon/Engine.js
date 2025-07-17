// recon/reconEngine.js
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import { exec } from 'child_process';
import { promisify } from 'util';
import { askUser } from '../communicatetoUser.js';
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

async function askMCPVulnFocused(target) {
  const prompt = `You are an advanced vulnerability assessment AI. Given the target: ${target}, select the most effective categories and tools from this map: ${JSON.stringify(toolMap, null, 2)}. For each tool, provide the optimal command-line arguments and a short purpose/description for each run, focusing on vulnerability discovery. You may use the same tool multiple times with different arguments for different purposes (e.g., nmap for port scan, script scan, vuln scan, etc). Return a JSON object with categories as keys and arrays of objects as values, each object having 'tool', 'args', and 'purpose' properties. Example: {"vulnerability_scan": [{"tool": "nmap", "args": "-sV --script vuln <target>", "purpose": "Nmap vuln script scan"}, {"tool": "nmap", "args": "-A <target>", "purpose": "Nmap aggressive scan"}]}`;
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
    // fallback: run all tools in all categories with no extra args
    const fallback = {};
    for (const [cat, tools] of Object.entries(toolMap)) {
      fallback[cat] = tools.map(tool => ({ tool, args: `<target>`, purpose: `Default run of ${tool}` }));
    }
    return fallback;
  }
}

async function fillPlaceholders(args, tool) {
  let filledArgs = args;
  const placeholders = args.match(/<[^>]+>/g);
  if (placeholders) {
    for (const ph of placeholders) {
      const value = await askUser(`Please provide a value for ${ph} in ${tool}:`);
      filledArgs = filledArgs.replace(ph, value);
    }
  }
  return filledArgs;
}

async function runToolCommandWithPurpose(tool, args, purpose, target) {
  let finalArgs = await fillPlaceholders(args, tool);
  let cmd = `${tool} ${finalArgs}`;
  // Confirm with user, allow skip or edit
  let confirmMsg = `About to run: ${cmd}\nPurpose: ${purpose}\nOptions: [y]es, [e]dit, [s]kip`;
  while (true) {
    const confirm = await askUser(confirmMsg);
    if (confirm.toLowerCase() === 'y') {
      break;
    } else if (confirm.toLowerCase() === 's') {
      return `[${tool} ${finalArgs}] Skipped by user.`;
    } else if (confirm.toLowerCase() === 'e') {
      finalArgs = await askUser(`Edit the arguments for ${tool}:\nCurrent: ${finalArgs}\nNew:`);
      cmd = `${tool} ${finalArgs}`;
    } else {
      confirmMsg = `Please enter [y]es, [e]dit, or [s]kip:`;
    }
  }
  try {
    const { stdout } = await execAsync(cmd);
    return `\n[${tool} ${finalArgs}]\nPurpose: ${purpose}\n${stdout}`;
  } catch (error) {
    return `\n[${tool} ${finalArgs} ERROR]\nPurpose: ${purpose}\n${error.message}`;
  }
}

export async function reconEngine(target) {
  console.log(chalk.bgBlue.white(`\n🤖 Asking MCP for vulnerability-focused recon plan for: ${target}`));
  const selected = await askMCPVulnFocused(target);
  console.log(chalk.bgCyan.black("\nMCP selected tools, arguments, and purposes:"));
  Object.entries(selected).forEach(([cat, arr]) => {
    console.log(chalk.yellow(cat) + ': ' + arr.map(obj => chalk.green(obj.tool + ' ' + obj.args) + chalk.white(' (' + obj.purpose + ')')).join(', '));
  });

  let results = [];
  for (const [category, arr] of Object.entries(selected)) {
    results.push(chalk.bold(`\n=== ${category} ===`));
    for (const { tool, args, purpose } of arr) {
      results.push(await runToolCommandWithPurpose(tool, args, purpose, target));
    }
  }

  // Print and summarize results
  const allResults = results.filter(Boolean).join('\n');
  console.log(chalk.bgGreen.black("\nRecon Results:"));
  console.log(allResults);

  // AI summary with Mistral
  const aiPrompt = `Summarize and analyze the following vulnerability assessment results for target ${target}. Provide actionable insights and next steps.\n${allResults}`;
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
