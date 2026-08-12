# Models and Settings

This artifact records the current source strings associated with the retained
experiment caches. Historical cache rows do not retain per-request prompt bytes,
provider request IDs, decoding settings, timestamps, or immutable model revisions.
The paper therefore does not claim byte-exact replay of the historical provider calls.

- Claude Sonnet 4.6: `claude-sonnet-4.6`
- Gemini 3.5 Flash: `gemini-3.5-flash`
- GPT-5.4 mini: `gpt-5.4-mini`
- Claude Opus 4.8: `claude-opus-4.8`
- GPT-5.5: `gpt-5.5`
- Gemini 3.1 Pro: `gemini-3.1-pro-preview`

Calls used provider defaults. Temperature, top-p, random seed, and resolved immutable
provider revision were not explicitly set or retained. The runners disabled tools,
used 60–120 second request timeouts, and retried failed calls three or four times. No
output-token limit or reasoning-effort setting was explicitly supplied.
