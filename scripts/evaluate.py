"""Evaluate the pipeline on eval/testset.jsonl. Reports metrics, ablation and a confusion matrix image.
Uses the LLM only if keys are configured; otherwise reports 'limited mode' honestly.
NOTE: the evidence patterns were written while looking at a few example messages, so score your OWN
fresh hold-out messages too and report both."""
import asyncio, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from app import classifier, config
from app.evidence import analyze_evidence, evidence_score
from app.pipeline import run
from app.schemas import AnalyzeRequest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SET = sys.argv[1] if len(sys.argv) > 1 else "testset"      # "testset" (dev, used while tuning) or "holdout" (report this one)
rows = [json.loads(l) for l in (ROOT / "eval" / f"{SET}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]


def metrics(pairs):
    tp = sum(1 for y, p in pairs if y == 1 and p == 1); fn = sum(1 for y, p in pairs if y == 1 and p == 0)
    fp = sum(1 for y, p in pairs if y == 0 and p == 1); tn = sum(1 for y, p in pairs if y == 0 and p == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0; rec = tp / (tp + fn) if tp + fn else 0.0
    return dict(tp=tp, fn=fn, fp=fp, tn=tn, accuracy=round((tp + tn) / len(pairs), 3), precision=round(prec, 3), recall=round(rec, 3),
                f1=round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0.0,
                false_alarm_rate=round(fp / (fp + tn), 3) if fp + tn else 0.0, miss_rate=round(fn / (tp + fn), 3) if tp + fn else 0.0)


async def main():
    y = [1 if r["label"] == "scam" else 0 for r in rows]
    full, ev_only, clf_only, details, uncertain = [], [], [], [], 0
    for r, yy in zip(rows, y):
        resp = await run(AnalyzeRequest(text=r["text"], mode="auto"))
        flagged = 1 if resp.label in ("suspicious", "high_risk") else 0
        uncertain += resp.label == "uncertain"
        items, _ = await analyze_evidence(r["text"], use_rdap=False)
        ev_only.append((yy, 1 if evidence_score(items) >= 30 else 0))
        p = classifier.predict_prob(r["text"]) or 0.0
        clf_only.append((yy, 1 if p >= 0.5 else 0))
        full.append((yy, flagged))
        details.append(dict(id=r["id"], label=r["label"], type=r["type"], pred=resp.label, score=resp.score, limited=resp.limited_mode))
    out = dict(n=len(rows), llm_used=any(not d["limited"] for d in details), uncertain_count=uncertain,
               full_pipeline=metrics(full), evidence_only=metrics(ev_only), classifier_only=metrics(clf_only))
    out["errors"] = [d for d in details if (d["label"] == "scam") != (d["pred"] in ("suspicious", "high_risk"))]
    (ROOT / "eval" / "results").mkdir(parents=True, exist_ok=True)
    (ROOT / "eval" / "results" / f"metrics_{SET}.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({k: v for k, v in out.items() if k != "errors"}, indent=1))
    print("misclassified:"); [print(" ", e) for e in out["errors"]]
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        m = out["full_pipeline"]; fig, ax = plt.subplots(figsize=(3.6, 3.2))
        ax.imshow([[m["tn"], m["fp"]], [m["fn"], m["tp"]]], cmap="Blues")
        for i, row in enumerate([[m["tn"], m["fp"]], [m["fn"], m["tp"]]]):
            for j, v in enumerate(row): ax.text(j, i, v, ha="center", va="center")
        ax.set_xticks([0, 1], ["genuine", "flagged"]); ax.set_yticks([0, 1], ["genuine", "scam"]); ax.set_title("Full pipeline")
        fig.tight_layout(); fig.savefig(ROOT / "eval" / "results" / f"confusion_matrix_{SET}.png", dpi=150)
    except ImportError:
        print("(matplotlib not installed: skipping chart)")

asyncio.run(main())
