// recon/tools/sslscan.js
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

export async function runSSLScan(target) {
  console.log('⚙️ Running SSLScan...');
  try {
    const { stdout } = await execAsync(`sslscan ${target}`);
    console.log(`📊 SSLScan Result:\n${stdout}`);
  } catch (error) {
    console.error(`❌ SSLScan Error: ${error.message}`);
  }
} 