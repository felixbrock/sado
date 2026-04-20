"""
Train the linear probe (README step 4) + sanity checks (step 6).

Loads activations from `probes/activations/{train,val,test}.pt`, trains a
1536->1 linear head with BCE + Adam + early stopping on val loss across
10 seeds, and reports mean +/- std of val acc / test acc / test FN-rate
(with Wilson upper bound). Also runs:
  - majority-class val baseline
  - shuffled-label control (should collapse to ~majority)
  - TF-IDF bag-of-words + LogReg baseline on the raw (command + goal) text
"""
import argparse
import json
import math
from pathlib import Path

import numpy as np
import torch
from torch import nn


def wilson_upper(k: int, n: int, z: float = 1.96) -> float:
    if n == 0:
        return 1.0
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return centre + half


def train_one(
    X_tr: torch.Tensor,
    y_tr: torch.Tensor,
    X_va: torch.Tensor,
    y_va: torch.Tensor,
    seed: int,
    *,
    patience: int = 5,
    max_epochs: int = 30,
    lr: float = 1e-3,
    bs: int = 64,
) -> tuple[nn.Linear, float]:
    torch.manual_seed(seed)
    d = X_tr.shape[1]
    model = nn.Linear(d, 1)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    n_pos = int((y_tr == 1).sum().item())
    n_neg = int((y_tr == 0).sum().item())
    pos_weight = torch.tensor([n_neg / max(n_pos, 1)])
    bce = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    best_loss = float("inf")
    best_state = {k: v.clone() for k, v in model.state_dict().items()}
    bad = 0

    for _ in range(max_epochs):
        perm = torch.randperm(len(X_tr))
        model.train()
        for i in range(0, len(X_tr), bs):
            idx = perm[i : i + bs]
            logits = model(X_tr[idx]).squeeze(-1)
            loss = bce(logits, y_tr[idx].float())
            opt.zero_grad()
            loss.backward()
            opt.step()

        model.eval()
        with torch.no_grad():
            val_loss = bce(model(X_va).squeeze(-1), y_va.float()).item()
        if val_loss < best_loss - 1e-6:
            best_loss = val_loss
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            bad = 0
        else:
            bad += 1
            if bad >= patience:
                break

    model.load_state_dict(best_state)
    return model, best_loss


def _metrics_from_preds(preds: np.ndarray, y: np.ndarray) -> dict:
    preds = np.asarray(preds).astype(int)
    y = np.asarray(y).astype(int)
    acc = float((preds == y).mean())
    deny = y == 1
    n_deny = int(deny.sum())
    fn = int(((preds == 0) & deny).sum())
    allow = y == 0
    n_allow = int(allow.sum())
    fp = int(((preds == 1) & allow).sum())
    return {
        "acc": acc,
        "fn": fn,
        "n_deny": n_deny,
        "fn_rate": fn / max(n_deny, 1),
        "fn_wilson_ub": wilson_upper(fn, n_deny),
        "fp": fp,
        "n_allow": n_allow,
        "fp_rate": fp / max(n_allow, 1),
        "fp_wilson_ub": wilson_upper(fp, n_allow),
    }


def compute_metrics(model: nn.Linear, X: torch.Tensor, y: torch.Tensor) -> dict:
    model.eval()
    with torch.no_grad():
        preds = (model(X).squeeze(-1) > 0).int().numpy()
    return _metrics_from_preds(preds, y.numpy())


def run_layer(
    splits: dict, layer_key: str, n_seeds: int
) -> tuple[list[dict], dict]:
    X_tr = splits["train"][layer_key].float()
    y_tr = splits["train"]["labels"].long()
    X_va = splits["val"][layer_key].float()
    y_va = splits["val"]["labels"].long()
    X_te = splits["test"][layer_key].float()
    y_te = splits["test"]["labels"].long()

    results = []
    for seed in range(n_seeds):
        model, val_loss = train_one(X_tr, y_tr, X_va, y_va, seed)
        results.append(
            {
                "seed": seed,
                "val_loss": val_loss,
                "val": compute_metrics(model, X_va, y_va),
                "test": compute_metrics(model, X_te, y_te),
            }
        )

    g = torch.Generator().manual_seed(9999)
    y_shuf = y_tr[torch.randperm(len(y_tr), generator=g)]
    model_shuf, _ = train_one(X_tr, y_shuf, X_va, y_va, seed=9999)
    shuf_metrics = compute_metrics(model_shuf, X_te, y_te)

    return results, shuf_metrics


def summarize(results: list[dict]) -> dict:
    def col(split: str, key: str) -> np.ndarray:
        return np.array([r[split][key] for r in results])

    return {
        "val_acc": (col("val", "acc").mean(), col("val", "acc").std()),
        "test_acc": (col("test", "acc").mean(), col("test", "acc").std()),
        "test_fn_rate": (col("test", "fn_rate").mean(), col("test", "fn_rate").std()),
        "test_fn_wilson": (col("test", "fn_wilson_ub").mean(), col("test", "fn_wilson_ub").std()),
        "test_fp_rate": (col("test", "fp_rate").mean(), col("test", "fp_rate").std()),
    }


def _build_texts(splits: dict, labeled_path: Path, bench_path: Path) -> dict:
    def load(p: Path) -> dict:
        return {
            json.loads(line)["id"]: json.loads(line)
            for line in p.read_text().splitlines()
            if line.strip()
        }

    labeled = load(labeled_path)
    bench = load(bench_path)

    def text_for(rid: str, src: dict) -> str:
        r = src[rid]
        return f"{r.get('command', '')} {' '.join(r.get('args', []))} {r.get('goal', '')}"

    return {
        "train": [text_for(i, labeled) for i in splits["train"]["ids"]],
        "val": [text_for(i, labeled) for i in splits["val"]["ids"]],
        "test": [text_for(i, bench) for i in splits["test"]["ids"]],
    }


def logreg_probe(splits: dict, layer_key: str) -> dict:
    """Probe of record: sklearn LogReg with class_weight='balanced'."""
    from sklearn.linear_model import LogisticRegression

    X_tr = splits["train"][layer_key].float().numpy()
    X_va = splits["val"][layer_key].float().numpy()
    X_te = splits["test"][layer_key].float().numpy()
    y_tr = splits["train"]["labels"].numpy()
    y_va = splits["val"]["labels"].numpy()
    y_te = splits["test"]["labels"].numpy()

    clf = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000)
    clf.fit(X_tr, y_tr)
    return {
        "val": _metrics_from_preds(clf.predict(X_va), y_va),
        "test": _metrics_from_preds(clf.predict(X_te), y_te),
    }


def shortcut_analysis(
    splits: dict, texts: dict, layer_key: str
) -> dict[str, float]:
    """Compare LogReg on BoW / activation / [BoW || activation].

    If [BoW || activation] doesn't beat BoW alone on val, activations add
    nothing beyond surface n-grams and this model/layer is the wrong lever.
    """
    from scipy.sparse import csr_matrix, hstack
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=20000)
    Xtr_t = vec.fit_transform(texts["train"])
    Xva_t = vec.transform(texts["val"])
    Xte_t = vec.transform(texts["test"])

    Xtr_h = splits["train"][layer_key].float().numpy()
    Xva_h = splits["val"][layer_key].float().numpy()
    Xte_h = splits["test"][layer_key].float().numpy()

    Xtr_c = hstack([csr_matrix(Xtr_h), Xtr_t]).tocsr()
    Xva_c = hstack([csr_matrix(Xva_h), Xva_t]).tocsr()
    Xte_c = hstack([csr_matrix(Xte_h), Xte_t]).tocsr()

    y_tr = splits["train"]["labels"].numpy()
    y_va = splits["val"]["labels"].numpy()
    y_te = splits["test"]["labels"].numpy()

    def fit_eval(Xtr, Xva, Xte) -> tuple[float, float]:
        clf = LogisticRegression(max_iter=2000, C=1.0, class_weight="balanced")
        clf.fit(Xtr, y_tr)
        return clf.score(Xva, y_va), clf.score(Xte, y_te)

    out: dict[str, float] = {}
    for name, Xtr, Xva, Xte in [
        ("bow_only", Xtr_t, Xva_t, Xte_t),
        ("activ_only", Xtr_h, Xva_h, Xte_h),
        ("bow_plus_activ", Xtr_c, Xva_c, Xte_c),
    ]:
        va, te = fit_eval(Xtr, Xva, Xte)
        out[f"{name}_val"] = va
        out[f"{name}_test"] = te
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--activations-dir", default="probes/activations")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--labeled-data", default="probes/dataset_labeled.jsonl")
    ap.add_argument("--bench-data", default="bench/adversarial_resistance/dataset.jsonl")
    ap.add_argument("--skip-bow", action="store_true")
    args = ap.parse_args()

    root = Path(args.activations_dir)
    splits = {
        name: torch.load(root / f"{name}.pt", weights_only=False)
        for name in ("train", "val", "test")
    }
    n_tr = len(splits["train"]["labels"])
    n_va = len(splits["val"]["labels"])
    n_te = len(splits["test"]["labels"])
    print(f"train={n_tr}  val={n_va}  test={n_te}")
    print(f"model revision: {splits['train']['meta']['model_revision']}")

    y_va = splits["val"]["labels"]
    maj = int((y_va == 1).sum() > (y_va == 0).sum())
    maj_acc = float((y_va == maj).float().mean())

    y_te = splits["test"]["labels"]
    n_deny_te = int((y_te == 1).sum().item())
    print(f"\n=== Baselines ===")
    print(f"val majority class    : class={maj}  acc={maj_acc:.3f}")
    print(f"test DENY prior       : {n_deny_te}/{n_te} = {n_deny_te/n_te:.3f}")

    texts = (
        None
        if args.skip_bow
        else _build_texts(splits, Path(args.labeled_data), Path(args.bench_data))
    )

    for layer_key in ("hidden_mid", "hidden_last"):
        print(f"\n=== Probe of record: LogReg on {layer_key} (class_weight=balanced) ===")
        lr = logreg_probe(splits, layer_key)
        print(f"val : acc={lr['val']['acc']:.3f}  FN={lr['val']['fn']}/{lr['val']['n_deny']} ({lr['val']['fn_rate']:.3f})  FP={lr['val']['fp']}/{lr['val']['n_allow']} ({lr['val']['fp_rate']:.3f})")
        print(f"test: acc={lr['test']['acc']:.3f}  FN={lr['test']['fn']}/{lr['test']['n_deny']} ({lr['test']['fn_rate']:.3f}, Wilson UB {lr['test']['fn_wilson_ub']:.3f})  FP={lr['test']['fp']}/{lr['test']['n_allow']} ({lr['test']['fp_rate']:.3f}, Wilson UB {lr['test']['fp_wilson_ub']:.3f})")

        print(f"\n--- nn.Linear variance check ({args.seeds} seeds, pos_weight balanced) ---")
        results, shuf = run_layer(splits, layer_key, args.seeds)
        s = summarize(results)
        print(f"val  acc       : {s['val_acc'][0]:.3f} +/- {s['val_acc'][1]:.3f}")
        print(f"test acc       : {s['test_acc'][0]:.3f} +/- {s['test_acc'][1]:.3f}")
        print(f"test FN-rate   : {s['test_fn_rate'][0]:.3f} +/- {s['test_fn_rate'][1]:.3f}")
        print(f"test FN Wilson : {s['test_fn_wilson'][0]:.3f} +/- {s['test_fn_wilson'][1]:.3f}")
        print(f"test FP-rate   : {s['test_fp_rate'][0]:.3f} +/- {s['test_fp_rate'][1]:.3f}")
        print(f"shuffled-label : test_acc={shuf['acc']:.3f} (should be ~{maj_acc:.2f})")

        if texts is not None:
            sh = shortcut_analysis(splits, texts, layer_key)
            print(f"  -- shortcut analysis (LogReg, same classifier, fair compare) --")
            print(f"  BoW only          : val={sh['bow_only_val']:.3f}  test={sh['bow_only_test']:.3f}")
            print(f"  Activation only   : val={sh['activ_only_val']:.3f}  test={sh['activ_only_test']:.3f}")
            print(f"  BoW || Activation : val={sh['bow_plus_activ_val']:.3f}  test={sh['bow_plus_activ_test']:.3f}")
            delta = sh["bow_plus_activ_val"] - sh["bow_only_val"]
            verdict = "adds signal" if delta > 0.005 else "redundant w/ BoW"
            print(f"  -> val delta (combined - bow): {delta:+.3f}  ({verdict})")


if __name__ == "__main__":
    main()
