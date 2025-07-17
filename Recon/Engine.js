// recon/reconEngine.js
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';
import { tools as allTools } from './Tools.js';

// Map tool names to their dynamic import paths and function names
const toolMap = {
  nmap: { path: './Tools/nmap.js', fn: 'runNmap' },
  amass: { path: './Tools/amass.js', fn: 'runAmass' },
  theHarvester: { path: './Tools/theHarvester.js', fn: 'runHarvester' },
  gobuster: { path: './Tools/gobuster.js', fn: 'runGobuster' },
  whatweb: { path: './Tools/whatweb.js', fn: 'runWhatWeb' },
  sslscan: { path: './Tools/sslscan.js', fn: 'runSSLScan' },
  whois: { path: './Tools/whois.js', fn: 'runWhois' },
};

async function askMCPWhichTools(target) {
  const prompt = `You are an advanced recon AI. Given the target: ${target}, select the most effective tools from this list: ${allTools.join(", ")}. 
For each tool, specify the order and a short reason for its use. Return a JSON array of tool names in the order to run, e.g. ["nmap", "whois"].`;
  try {
    const aiResult = await mistral.chat.complete({
      model: "mistral-large-latest",
      messages: [
        { role: "user", content: prompt }
      ]
    });
    const content = aiResult.choices?.[0]?.message?.content;
    // Try to extract JSON array from the response
    const match = content.match(/\[.*\]/s);
    if (match) {
      return JSON.parse(match[0]);
    }
    // fallback: try to parse whole content
    return JSON.parse(content);
  } catch (err) {
    console.log(chalk.red("\nAI tool selection failed: " + err.message));
    // fallback: run all tools
    return allTools;
  }
}

export async function reconEngine(target) {
  console.log(chalk.bgBlue.white(`\n🤖 Asking MCP which tools to run for: ${target}`));
  const selectedTools = await askMCPWhichTools(target);
  console.log(chalk.bgCyan.black("\nMCP selected tools:") + " " + selectedTools.map(t => chalk.yellow(t)).join(chalk.white(", ")));

  let results = [];
  for (const toolName of selectedTools) {
    const tool = toolMap[toolName];
    if (!tool) {
      results.push(`Tool ${toolName} not found.`);
      continue;
    }
    try {
      const mod = await import(tool.path);
      const fn = mod[tool.fn];
      if (typeof fn === 'function') {
        results.push(await fn(target));
      } else {
        results.push(`Function ${tool.fn} not found in ${tool.path}`);
      }
    } catch (err) {
      results.push(`Error running ${toolName}: ${err.message}`);
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

// For compatibility with index.js
export async function runChunkedRecon(target) {
  await reconEngine(target);
}
