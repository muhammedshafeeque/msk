// recon/tools/whatweb.js
import { exec } from 'child_process';
import { promisify } from 'util';
const execAsync = promisify(exec);

export async function runWhatWeb(target) {
  console.log('⚙️ Running WhatWeb...');
  try {
    const { stdout } = await execAsync(`whatweb ${target}`);
    console.log(`📊 WhatWeb Result:\n${stdout}`);
  } catch (error) {
    console.error(`❌ WhatWeb Error: ${error.message}`);
  }
} 