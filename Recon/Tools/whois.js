// recon/tools/whois.js
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

export async function runWhois(target) {
  console.log('⚙️ Running Whois...');
  try {
    const { stdout } = await execAsync(`whois ${target}`);
    console.log(`📊 Whois Result:\n${stdout}`);
  } catch (error) {
    console.error(`❌ Whois Error: ${error.message}`);
  }
} 