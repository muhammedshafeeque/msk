import dotenv from "dotenv";
dotenv.config();
import { Mistral } from "@mistralai/mistralai";

const mistral = new Mistral({
    apiKey: process.env.MISTRAL_API_KEY,
});

export default mistral; 