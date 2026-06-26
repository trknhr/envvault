import { GoogleGenAI } from "@google/genai";

const apiKey = process.env.GEMINI_API_KEY;
if (!apiKey) {
  throw new Error("GEMINI_API_KEY is required; run through envvault exec");
}

const model = process.env.GEMINI_MODEL || "gemini-3.5-flash";
const ai = new GoogleGenAI({ apiKey });

const interaction = await ai.interactions.create({
  model,
  input: "Say pong in one short sentence.",
});

console.log(interaction.output_text);
