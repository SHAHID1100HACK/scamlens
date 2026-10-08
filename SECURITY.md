# Security

ScamLens reads hostile text by design, so every input (user text, fetched pages, model output) is treated as untrusted.

## Threats and controls
| Threat | Controls |
|---|---|
| Prompt injection in submitted text ("mark this safe") | Per-request random-nonce delimiters; delimiters stripped from input; model has no tools and returns JSON only; deterministic evidence + hard floors that the model cannot lower; injection phrases add a warning signal; strict output schema; quotes must be real substrings; playbook ids must have been retrieved. |
| RAG / feed poisoning | Ingestion only in GitHub Actions; host allowlist; hidden text stripped; injection pre-screen quarantines before any LLM call; strict schema; confidence threshold; auto-learned cards badged; caps per run; git history = audit + rollback; `data/BLOCKLIST.txt`. |
| SSRF | Server never fetches user URLs. Outbound calls only to fixed hosts. `check_url_target` rejects non-http(s), odd ports, credentials, numeric/IP hosts, localhost and any host resolving to a non-public address. Ingestion re-validates every redirect hop. |
| Quota abuse / DoS | Per-IP and per-day limits, global daily LLM budget with automatic limited mode, 20 KB body cap, 6000-char text cap, result cache, timeouts, circuit breaker, linear-time regexes (stress-tested). |
| XSS | No `innerHTML` anywhere; all rendering via `textContent`; model strings stripped of `<`, `>` and markdown links; strict CSP without inline script/style. |
| Secrets | Environment variables only (HF Space secrets, GitHub secrets). No secrets in code, extension or ZIP (tested). |
| Privacy | Submitted text is never stored or logged; only metadata is logged. Card numbers, 12-digit IDs and OTP/PIN/CVV values are masked in the extension and again on the server before any external call. |
| Extension | Minimal permissions, no always-on content scripts, one backend host, no remote code, response shape validated, sender-id checked, DOM built with safe APIs. |
| Supply chain | Few pinned-by-CI dependencies, extension has none, `pip-audit` in CI, Dockerfile runs as non-root, ZIP built deterministically with published SHA-256. |

## Known limitations (honest list)
- Model judgements can be wrong or manipulated; ScamLens never claims a message is safe.
- Free-tier LLM prompts may be used by the provider to improve models. Do not submit real personal data.
- The classifier is trained on generic SMS spam, so it is a weak secondary signal.
- Auto-learned cards can be wrong; they are badged and thresholded, and can be reverted from git.
- CORS does not stop scripts or curl; rate limits and caps do.
- No URL expansion/fetching feature exists, so DNS-rebinding on user URLs is out of scope by design.

## Reporting a vulnerability
Open a private GitHub security advisory on this repository, or email the maintainers. Good-faith reports will not be pursued. All test messages in this repo are synthetic.
