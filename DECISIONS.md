# Decisions and assumptions
- **Retrieval uses TF-IDF cosine, not neural embeddings.** No model download, no heavy dependency, runs on a free CPU Space. A neural embedder (e.g. fastembed) can be swapped into `app/rag.py::Store._build/retrieve` later.
- **Classifier weight is low (0.20 with AI, 0.25 in limited mode).** It is trained on UCI SMS spam (promotional spam), which fits scams only partly. Chosen using the *dev* eval set only.
- **Limited-mode thresholds are lower** (suspicious from 20, high from 55) because without the AI opinion total scores run lower; being cautious is the safer failure.
- **URL expansion (shortener following) is not implemented** (spec item C1). The SSRF guard `check_url_target` exists and is tested, but the server never fetches user URLs. Only fixed hosts are contacted: rdap.org, the LLM providers, KNOWLEDGE_URL.
- **Ingestion runs only in GitHub Actions.** The public server just pulls validated JSON from `KNOWLEDGE_URL`.
- **Evaluation:** `eval/testset.jsonl` is the dev set (rules were tuned looking at it, so its numbers are optimistic). `eval/holdout.jsonl` was run once after tuning; report that one.
- **Gemini and fallback adapters were written from API knowledge and are unit-tested with mocks only.** Make one real call with your key before relying on them.
- **Client IP:** right-most `X-Forwarded-For` entry is used behind the platform proxy.
- **Extension host permission** is placeholder-substituted at package time from `SPACE_HOST`; for local dev the manifest also allows `http://localhost:7860`.
