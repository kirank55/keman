#!/usr/bin/env python3
"""Stream a chat completion through Keman using the official OpenAI Python SDK.

The SDK talks to {base_url}/chat/completions, so base_url must include /v1:

    pip install openai
    export KEMAN_KEY=kmn_...
    python3 examples/sdk_stream.py
"""

import os
import sys

try:
    from openai import OpenAI
except ImportError:
    sys.exit("pip install openai")

key = os.environ.get("KEMAN_KEY") or os.environ.get("OPENAI_API_KEY")
if not key:
    sys.exit("set KEMAN_KEY to a virtual key")

client = OpenAI(
    base_url=os.environ.get("KEMAN_BASE_URL", "http://127.0.0.1:8080/v1"),
    api_key=key,
)
stream = client.chat.completions.create(
    model=os.environ.get("KEMAN_MODEL", "gpt-4o-mini"),
    messages=[{"role": "user", "content": "Say hi in one word."}],
    stream=True,
)
for chunk in stream:
    if not chunk.choices:
        continue
    delta = chunk.choices[0].delta.content
    if delta:
        print(delta, end="", flush=True)
print()
