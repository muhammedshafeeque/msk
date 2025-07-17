import chalk from "chalk"
import { askForTarget } from "./communicatetoUser.js"
import { validateAndNormalizeTarget } from "./validator.js"
import { runChunkedRecon } from "./Recon/Engine.js"

const main = async () => {
    const target = await askForTarget()
    console.log(chalk.green("Target URL: " + chalk.red(target)))
    const normalizedTarget = validateAndNormalizeTarget(target)
    console.log(chalk.blue("Normalized Target: ") + chalk.yellow(normalizedTarget))
    await runChunkedRecon(normalizedTarget)
}

main()
