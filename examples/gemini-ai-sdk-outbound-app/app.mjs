import { existsSync } from "node:fs";
import { loadEnvFile } from "node:process";
import { fileURLToPath } from "node:url";

import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { generateText } from "ai";

const envFile = fileURLToPath(new URL(".env", import.meta.url));
if (existsSync(envFile)) {
  loadEnvFile(envFile);
}

const apiKey = process.env.GEMINI_API_KEY;
if (!apiKey) {
  throw new Error("GEMINI_API_KEY is required");
}

const baseURL =
  process.env.GEMINI_BASE_URL ||
  "https://generativelanguage.googleapis.com/v1beta/openai";
const model = process.env.GEMINI_MODEL || "gemini-3.5-flash";
const prompt =
  process.argv.slice(2).join(" ") || "Say pong in one short sentence.";

const gemini = createOpenAICompatible({
  baseURL,
  name: "gemini",
  apiKey,
});

const { text } = await generateText({
  model: gemini.chatModel(model),
  prompt,
});

console.log(text);
