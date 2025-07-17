// Progress Helper - Provides guidance for long-running reconnaissance
import chalk from 'chalk';

export function showProgressTips() {
  console.log(chalk.bgBlue.white(`\n📊 RECONNAISSANCE PROGRESS TIPS`));
  console.log(chalk.cyan(`\n🔄 Current Status: Running reconnaissance tools...`));
  console.log(chalk.yellow(`\n⏱️  Expected Timeline:`));
  console.log(`   • Passive reconnaissance: 2-5 minutes`);
  console.log(`   • Active reconnaissance: 5-15 minutes`);
  console.log(`   • Intelligence processing: 1-2 minutes`);
  console.log(`   • Total estimated time: 10-25 minutes`);
  
  console.log(chalk.green(`\n💡 What's happening now:`));
  console.log(`   • Tools are gathering intelligence about the target`);
  console.log(`   • Some tools (like recon-ng, amass) can take several minutes`);
  console.log(`   • The system will automatically proceed to the next phase`);
  
  console.log(chalk.magenta(`\n🎯 Next phases:`));
  console.log(`   1. ✅ Passive Reconnaissance (in progress)`);
  console.log(`   2. 🚀 Active Reconnaissance`);
  console.log(`   3. ⚡ Conditional Enumeration`);
  console.log(`   4. 🧠 Fast Intelligence Engine Processing`);
  console.log(`   5. 🧠 Contextual Intelligence Engine Processing`);
  console.log(`   6. 🔍 Basic Vuln Extractor Processing`);
  console.log(`   7. 💥 Exploit Finder & Fetcher Processing`);
  
  console.log(chalk.blue(`\n📁 Reports will be generated in:`));
  console.log(`   ./reports/target_timestamp/`);
  console.log(`   • intel_summary.json - Structured intelligence data`);
  console.log(`   • summary_report.md - Human-readable report`);
  console.log(`   • contextual_report.md - Business impact analysis`);
  console.log(`   • vuln_report.md - Vulnerability assessment`);
  console.log(`   • exploit_report.md - Exploit availability`);
  
  console.log(chalk.yellow(`\n⚠️  If a tool seems stuck:`));
  console.log(`   • Press Ctrl+C to skip the current tool`);
  console.log(`   • The system will continue with the next tool`);
  console.log(`   • You can always re-run specific tools later`);
  
  console.log(chalk.green(`\n✅ The system is working correctly!`));
  console.log(`   Just be patient - comprehensive reconnaissance takes time.`);
}

export function showCurrentPhase(phase, toolIndex, totalTools) {
  const phases = [
    'Passive Reconnaissance',
    'Active Reconnaissance', 
    'Conditional Enumeration',
    'Fast Intelligence Engine',
    'Contextual Intelligence Engine',
    'Basic Vuln Extractor',
    'Exploit Finder & Fetcher'
  ];
  
  console.log(chalk.bgBlue.white(`\n🔄 CURRENT PHASE: ${phases[phase - 1]}`));
  if (toolIndex && totalTools) {
    console.log(chalk.cyan(`📊 Progress: Tool ${toolIndex}/${totalTools}`));
  }
} 