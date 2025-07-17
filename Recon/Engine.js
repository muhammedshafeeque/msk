// recon/reconEngine.js
import { runNmap } from './Tools/nmap.js';
import { runAmass } from './Tools/amass.js';
import { runGobuster } from './Tools/gobuster.js';
import { runHarvester } from './Tools/theHarvester.js';
import { runWhatWeb } from './Tools/whatweb.js';
import { runSSLScan } from './Tools/sslscan.js';
import { runWhois } from './Tools/whois.js';
import { chunk } from 'chunki';
import chalk from 'chalk';
import mistral from '../Config/Mistra.js';

const reconTools = [
  "nmap",
  "amass",
  "theHarvester",
  "gobuster",
  "whatweb",
  "sslscan",
  "whois"
];

export async function reconEngine(target) {
  console.log(`🔍 Starting Recon on: ${target}\n`);
  let results = [];

  results.push(await runNmap(target));
  results.push(await runAmass(target));
  results.push(await runHarvester(target));
  results.push(await runGobuster(target));
  results.push(await runWhatWeb(target));
  results.push(await runSSLScan(target));
  results.push(await runWhois(target));

  console.log(`✅ Recon Completed for ${target}`);
  return results.join('\n');
}

export async function runChunkedRecon(target) {
  const toolChunks = chunk(reconTools, 2);
  console.log(chalk.bgMagenta.bold("\nRunning recon in chunks:"));
  let allResults = [];
  for (const [i, tools] of toolChunks.entries()) {
    console.log(chalk.bgCyan.black(`\nChunk ${i + 1}: `) + tools.map(t => chalk.yellow(t)).join(chalk.white(", ")));
    const chunkResult = await reconEngine(target);
    allResults.push(chunkResult);
    console.log(chalk.greenBright(`Finished chunk ${i + 1}\n`));
  }
  console.log(chalk.bgGreen.black("\nAll recon chunks completed!"));

  // AI summary with Mistral
  const aiPrompt = `Summarize the following recon results for target ${target}:\n${allResults.join('\n')}`;
  try {
    const aiResult = await mistral.chat.complete({
      model: "mistral-large-latest",
      messages: [
        { role: "user", content: aiPrompt }
      ]
    });
    console.log(chalk.bgBlue.white("\nAI Summary:"));
    console.log(aiResult.choices?.[0]?.message?.content || JSON.stringify(aiResult));
  } catch (err) {
    console.log(chalk.red("\nAI summary failed: " + err.message));
  }
}
