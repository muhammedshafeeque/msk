// recon/tools/nmap.js
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

export async function runNmap(target) {
  console.log('⚙️ Running Nmap...');
  try {
    const { stdout } = await execAsync(`nmap -sV -O ${target}`);
    console.log(`📊 Nmap Result:\n${stdout}`);
  } catch (error) {
    console.error(`❌ Nmap Error: ${error.message}`);
  }
}
