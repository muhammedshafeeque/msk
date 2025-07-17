import chalk from "chalk"
import readline from "readline"

export const askForTarget = async () => {
    console.log(chalk.blue("Enter the target URL"))
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    })
    const target = await new Promise(resolve => rl.question("", resolve))
    rl.close()
    return target
}