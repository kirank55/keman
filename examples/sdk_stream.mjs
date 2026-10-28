#!/usr/bin/env node
// Stream a chat completion through Keman using the official OpenAI Node SDK.
// The SDK talks to {baseURL}/chat/completions, so baseURL must include /v1:
//   npm install openai
//   KEMAN_KEY=kmn_... node examples/sdk_stream.mjs

import OpenAI from "openai";

const key = process.env.KEMAN_KEY || process.env.OPENAI_API_KEY;
if (!key) {
  console.error("set KEMAN_KEY to a virtual key");
  process.exit(1);
}

const client = new OpenAI({
  baseURL: process.env.KEMAN_BASE_URL || "http://127.0.0.1:8080/v1",
  apiKey: key,
});

const stream = await client.chat.completions.create({
  model: process.env.KEMAN_MODEL || "gpt-4o-mini",
  messages: [{ role: "user", content: "Say hi in one word." }],
  stream: true,
});

for await (const chunk of stream) {
  const delta = chunk.choices?.[0]?.delta?.content;
  if (delta) {
    process.stdout.write(delta);
  }
}
process.stdout.write("\n");
