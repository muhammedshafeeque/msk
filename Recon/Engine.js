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

  await runNmap(target);
  await runAmass(target);
  await runHarvester(target);
  await runGobuster(target);
  await runWhatWeb(target);
  await runSSLScan(target);
  await runWhois(target);

  console.log(`✅ Recon Completed for ${target}`);
}

export async function runChunkedRecon(target) {
  const toolChunks = chunk(reconTools, 2);
  console.log(chalk.bgMagenta.bold("\nRunning recon in chunks:"));
  for (const [i, tools] of toolChunks.entries()) {
    console.log(chalk.bgCyan.black(`\nChunk ${i + 1}: `) + tools.map(t => chalk.yellow(t)).join(chalk.white(", ")));
    await reconEngine(target);
    console.log(chalk.greenBright(`Finished chunk ${i + 1}\n`));
  }
  console.log(chalk.bgGreen.black("\nAll recon chunks completed!"));
}
