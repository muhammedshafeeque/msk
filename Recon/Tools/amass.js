// recon/tools/amass.js
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

export async function runAmass(target) {
  console.log('⚙️ Running Amass...');
  try {
    const { stdout } = await execAsync(`amass enum -d ${target}`);
    console.log(`📊 Amass Result:\n${stdout}`);
  } catch (error) {
    console.error(`❌ Amass Error: ${error.message}`);
  }
} 