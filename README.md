---
title: ScamLens
emoji: 🔍
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
---

# 🔍 ScamLens — explainable scam checks (ForgeHacks 2026 · AI + Cybersecurity)

Paste or select a job offer, marketplace chat, message or link. ScamLens gives a **risk score and explains it**: verbatim red-flag quotes, the matched scam playbook, and safe next steps. It **never says something is "safe"**, and its knowledge base **keeps learning new scams** from public alert feeds. It is built to resist abuse itself (see [SECURITY.md](SECURITY.md)).

**Inspiration:** Trustee (ESSEC 2025 hackathon), a Chrome extension that scored fraud risk on listings and chats with RAG + LLM reasoning, with explainability as its core strength.

- **Live demo:** `https://<USERNAME>-scamlens.hf.space` (free Space; it may take a minute to wake)
- **Extension download:** `/install` page of the demo (ZIP + checksum + 4 install steps)
- **Video:** _add YouTube link_

## How it works
1. **Evidence engine** (rules): advance fees, OTP/PIN requests, risky payment methods, secrecy and urgency pressure, lookalike / brand-new / shortened links (domain age via RDAP).
2. **Classifier**: TF-IDF + logistic regression trained on the UCI SMS Spam Collection (low weight; generic-spam model).
3. **RAG**: retrieval over 43 hand-written scam playbooks plus auto-learned ones.
4. **LLM reasoning** (Gemini free tier, optional fallback provider): strict JSON; the server verifies every quote is real text and every playbook was actually retrieved.
5. **Fusion scoring** with hard floors (advance-fee, credential requests) the model cannot lower, an honest **"not sure"** state, and a clear **limited mode** if the AI is unavailable.
6. **Self-updating knowledge**: a daily GitHub Action reads allowlisted scam-alert feeds, extracts cards with the LLM, validates/quarantines them and commits `data/auto_cards.json`; the app pulls it with **Update knowledge now**. (Retrieval update, not model fine-tuning.)

## Results (honest)
Evaluated in **limited mode** (no LLM key was available while building), on synthetic messages I wrote.

| Set | n | Accuracy | Recall | False-alarm rate |
|---|---|---|---|---|
| Dev set (`eval/testset.jsonl`, rules were tuned on it → optimistic) | 65 | 1.00 | 1.00 | 0.00 |
| **Hold-out (`eval/holdout.jsonl`, run once, not tuned on)** | 28 | **0.82** | **0.71** | **0.07** |

Ablation on the hold-out: evidence only 0.79, classifier only 0.61, full pipeline 0.82. Re-run `python scripts/evaluate.py holdout` **with your LLM key** and report those numbers; the AI step is expected to help recall but this was not measured here. Small test sets mean wide uncertainty.

## Run locally
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python scripts/train_classifier.py
python scripts/package_extension.py                     # builds the extension ZIP for /install
cp .env.example .env                                    # then fill in GEMINI_API_KEY and LLM_MODEL (see AI Studio)
export $(grep -v '^#' .env | xargs)                     # or set the variables in your shell
uvicorn app.main:app --port 7860
pytest -q
```
Without keys the app runs in **limited mode** (rules + classifier). Open http://localhost:7860.

## Deploy free (Hugging Face Space)
1. Create a **Docker** Space (public, CPU basic). Add secrets `GEMINI_API_KEY` (and optional `FALLBACK_API_KEY`) and variables `LLM_MODEL`, `KNOWLEDGE_URL` (raw GitHub URL of `data/auto_cards.json`), `ALLOWED_ORIGINS`.
2. Push this repo to the Space (`git remote add space https://huggingface.co/spaces/<USERNAME>/scamlens && git push space main`).
3. Open the Space URL, then `/install` to download the extension.
Add `GEMINI_API_KEY` as a GitHub Actions secret, verify the URLs in `data/sources.yaml`, and run the **ingest-scam-feeds** workflow once.

## Install the extension
Download from the demo's `/install` page → unzip → `chrome://extensions` → Developer mode → **Load unpacked**. Select text → right-click → **Check with ScamLens**.

## Disclaimer
ScamLens can be wrong. "No strong red flags" does not mean safe. Verify through official channels. Demo examples are synthetic; do not paste real personal data.

Dataset credit: UCI SMS Spam Collection (CC BY 4.0). License: MIT.
