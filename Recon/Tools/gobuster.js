// recon/tools/gobuster.js
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

export async function runGobuster(target) {
  console.log('⚙️ Running Gobuster...');
  try {
    // Example: gobuster dir -u http://example.com -w /usr/share/wordlists/dirb/common.txt
    const { stdout } = await execAsync(`gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt`);
    console.log(`📊 Gobuster Result:\n${stdout}`);
  } catch (error) {
    console.error(`❌ Gobuster Error: ${error.message}`);
  }
} 