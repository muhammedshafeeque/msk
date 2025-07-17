// recon/tools/theHarvester.js
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

export async function runHarvester(target) {
  console.log('⚙️ Running theHarvester...');
  try {
    const { stdout } = await execAsync(`theHarvester -d ${target} -b all`);
    console.log(`📊 theHarvester Result:\n${stdout}`);
  } catch (error) {
    console.error(`❌ theHarvester Error: ${error.message}`);
  }
} 