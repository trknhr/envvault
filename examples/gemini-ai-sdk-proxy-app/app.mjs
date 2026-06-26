import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { generateText } from "ai";

const proxyURL = process.env.ENVVAULT_PROXY_URL;
const proxyToken = process.env.ENVVAULT_PROXY_TOKEN;

if (!proxyURL) {
  throw new Error("ENVVAULT_PROXY_URL is required; run through envvault exec");
}
if (!proxyToken) {
  throw new Error("ENVVAULT_PROXY_TOKEN is required; run through envvault exec");
}

const model = process.env.GEMINI_MODEL || "gemini-3.5-flash";
const gemini = createOpenAICompatible({
  baseURL: proxyURL,
  name: "gemini",
  apiKey: proxyToken,
});

const { text } = await generateText({
  model: gemini.chatModel(model),
  prompt: "Say pong in one short sentence.",
});

console.log(text);
