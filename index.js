import chalk from "chalk"
import { askForTarget } from "./communicatetoUser.js"
import { validateAndNormalizeTarget } from "./validator.js"
import { runChunkedRecon } from "./Recon/Engine.js"

const main = async () => {
    const target = await askForTarget()
    console.log(chalk.green("Target URL: " + chalk.red(target)))
    const normalizedResult = await validateAndNormalizeTarget(target)
    if (normalizedResult.isValid) {
        console.log(chalk.blue("Normalized Target: ") + chalk.yellow(normalizedResult.normalized))
        if (normalizedResult.ip) {
            console.log(chalk.blue("Resolved IP: ") + chalk.yellow(normalizedResult.ip))
        }
        await runChunkedRecon(normalizedResult.normalized)
    } else {
        console.log(chalk.red("Invalid input: ") + normalizedResult.reason)
    }
}

main()
