#!/usr/bin/env python3
"""
Microbenchmark for the consult-scoped anonymous-credential access path.

What this script does:
  * measures the primitive operations used by the cost model;
  * combines measured primitive timings with the paper's operation counts;

Recommended paper command, after installing native dependencies:
  python3 op_costs_measured.py --reps 1000 --prim-reps 200 --require-native

Native dependencies:
  pip install gmpy2 petrelic
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import secrets
import statistics as st
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Tuple

# Operation names used
ORDER = ["E1", "E2", "ET", "P", "En2", "H"]
NICE = {
    "E1": "G1 exp",
    "E2": "G2 exp",
    "ET": "GT exp",
    "P": "pairing",
    "En2": "exp mod n^2",
    "H": "SHA-256",
}

# Only used with --allow-model. Keep deliberately visible and explicit.
MODELED_MS = {"E1": 0.12, "E2": 0.25, "ET": 0.45, "P": 0.55, "En2": 8.00, "H": 0.001}

Runner = Callable[[], object]


def now_ns() -> int:
    return time.perf_counter_ns()


def summarize(samples_ms: Iterable[float]) -> Dict[str, float]:
    xs = list(samples_ms)
    if not xs:
        raise ValueError("cannot summarize an empty sample set")
    xs_sorted = sorted(xs)
    q1 = xs_sorted[int(0.25 * (len(xs_sorted) - 1))]
    q3 = xs_sorted[int(0.75 * (len(xs_sorted) - 1))]
    return {
        "mean": st.mean(xs),
        "stdev": st.stdev(xs) if len(xs) > 1 else 0.0,
        "median": st.median(xs),
        "min": min(xs),
        "max": max(xs),
        "q1": q1,
        "q3": q3,
        "n": len(xs),
    }


def time_primitive(run: Runner, reps: int, batch: int) -> list[float]:
    """Return per-operation samples in ms, each sample amortized over batch ops."""
    for _ in range(min(10, batch)):
        run()
    out = []
    for _ in range(reps):
        t0 = now_ns()
        for _ in range(batch):
            run()
        t1 = now_ns()
        out.append((t1 - t0) / batch / 1_000_000.0)
    return out


def rand_odd(bits: int) -> int:
    return secrets.randbits(bits) | 1 | (1 << (bits - 1))


def build_en2_runner(nbits: int, pool: int) -> Tuple[Runner, str, bool]:
    """Return exp-mod-n^2 runner, backend label, and whether backend is native/representative."""
    try:
        import gmpy2

        mp = gmpy2.mpz
        powmod = gmpy2.powmod
        backend = f"gmpy2/GMP {gmpy2.mp_version()}"
        native = True
    except Exception:
        mp = int
        powmod = pow
        backend = "Python built-in pow; measured but not production-representative"
        native = False

    n = mp(rand_odd(nbits // 2)) * mp(rand_odd(nbits // 2))
    n2 = n * n
    base = mp(2 + secrets.randbelow(int(n2) - 3))
    exps = [mp(random.getrandbits(nbits) | (1 << (nbits - 1))) for _ in range(pool)]
    idx = [0]
    powmod(base, exps[0], n2) 

    def run() -> object:
        e = exps[idx[0] % pool]
        idx[0] += 1
        return powmod(base, e, n2)

    return run, backend, native


def build_hash_runner(pool: int) -> Tuple[Runner, str, bool]:
    msgs = [secrets.token_bytes(256) for _ in range(pool)]
    idx = [0]

    def run() -> bytes:
        m = msgs[idx[0] % pool]
        idx[0] += 1
        return hashlib.sha256(m).digest()

    return run, "hashlib SHA-256", True


def build_petrelic_runners(pool: int) -> Tuple[Dict[str, Runner], Dict[str, str]]:
    from petrelic.multiplicative.pairing import G1, G2 

    g1 = G1.generator()
    g2 = G2.generator()
    order = G1.order()
    xs = [order.random() for _ in range(pool)]
    gt = g1.pair(g2)
    idx = [0]

    def nx():
        x = xs[idx[0] % pool]
        idx[0] += 1
        return x

    runners = {
        "E1": lambda: g1 ** nx(),
        "E2": lambda: g2 ** nx(),
        "ET": lambda: gt ** nx(),
        "P": lambda: g1.pair(g2),
    }
    backend = {op: "petrelic/RELIC BLS-381" for op in ("E1", "E2", "ET", "P")}
    return runners, backend


def build_py_ecc_runners(pool: int) -> Tuple[Dict[str, Runner], Dict[str, str]]:
    from py_ecc.optimized_bls12_381 import G1, G2, curve_order, multiply, pairing

    xs = [secrets.randbelow(curve_order - 1) + 1 for _ in range(pool)]
    gt = pairing(G2, G1, final_exponentiate=True)
    idx = [0]

    def nx() -> int:
        x = xs[idx[0] % pool]
        idx[0] += 1
        return x

    runners = {
        "E1": lambda: multiply(G1, nx()),
        "E2": lambda: multiply(G2, nx()),
        "ET": lambda: gt ** nx(),
        "P": lambda: pairing(G2, G1, final_exponentiate=True),
    }
    backend = {op: "py_ecc optimized_bls12_381; pure Python, not production-representative" for op in ("E1", "E2", "ET", "P")}
    return runners, backend


def build_pairing_runners(pairing_backend: str, pool: int) -> Tuple[Dict[str, Runner], Dict[str, str], bool]:
    errors = []

    if pairing_backend in ("auto", "petrelic"):
        try:
            runners, backend = build_petrelic_runners(pool)
            return runners, backend, True
        except Exception as e:
            errors.append(f"petrelic unavailable: {e}")
            if pairing_backend == "petrelic":
                raise RuntimeError("; ".join(errors))

    if pairing_backend in ("auto", "py_ecc"):
        try:
            runners, backend = build_py_ecc_runners(pool)
            return runners, backend, False
        except Exception as e:
            errors.append(f"py_ecc unavailable: {e}")
            if pairing_backend == "py_ecc":
                raise RuntimeError("; ".join(errors))

    raise RuntimeError("; ".join(errors) if errors else "no pairing backend selected")


def build_runners(nbits: int, pool: int, pairing_backend: str) -> Tuple[Dict[str, Runner], Dict[str, str], Dict[str, bool]]:
    runners: Dict[str, Runner] = {}
    backend: Dict[str, str] = {}
    native: Dict[str, bool] = {}

    runners["En2"], backend["En2"], native["En2"] = build_en2_runner(nbits, pool)
    runners["H"], backend["H"], native["H"] = build_hash_runner(pool)

    pairing_runners, pairing_backend_labels, pairing_native = build_pairing_runners(pairing_backend, pool)
    runners.update(pairing_runners)
    backend.update(pairing_backend_labels)
    for op in ("E1", "E2", "ET", "P"):
        native[op] = pairing_native

    return runners, backend, native


ZERO = {k: 0 for k in ORDER}


def vec(**kw: int) -> Dict[str, int]:
    v = dict(ZERO)
    v.update(kw)
    return v


def add(a: Dict[str, int], b: Dict[str, int]) -> Dict[str, int]:
    return {k: a[k] + b[k] for k in ORDER}


def groth_randomize(k: int) -> Dict[str, int]:
    return vec(E1=k + 1, E2=1)


def groth_verify(k: int) -> Dict[str, int]:
    return vec(P=2, E1=k)


def cost_model(k1: int = 5, k2: int = 5, n_disc: int = 4, L: int = 2) -> Tuple[Dict[str, Dict[str, int]], Dict[str, int]]:
    w = k1 + k2 + 3
    ph: Dict[str, Dict[str, int]] = {}
    ph["Issuance (per doctor)"] = add(vec(E1=k1 + 1, E2=1), vec(E1=1, H=1))
    ph["Policy auth (PDP+A)"] = vec(E1=3, H=2)
    ph["Delegation: A sign"] = add(vec(E1=k2 + 1, E2=1), vec(H=1))
    ph["Delegation: B verify"] = add(add(groth_verify(k1), groth_verify(k2)), vec(E1=2, H=1))

    gen = vec()
    gen = add(gen, groth_randomize(k1))
    gen = add(gen, groth_randomize(k1))
    gen = add(gen, groth_randomize(k2))
    gen = add(gen, vec(ET=w))
    gen = add(gen, vec(En2=4))
    gen = add(gen, vec(En2=2, E1=2))
    gen = add(gen, vec(H=3))
    ph["Access proof: GENERATE (Dr B)"] = gen

    ver = vec(E1=2)
    ver = add(ver, groth_verify(k1))
    ver = add(ver, groth_verify(k1))
    ver = add(ver, groth_verify(k2))
    ver = add(ver, vec(ET=w))
    ver = add(ver, vec(En2=4, E1=2))
    ver = add(ver, vec(H=3))
    ph["Access proof: VERIFY (Gateway)"] = ver
    return ph, {"k1": k1, "k2": k2, "n_disc": n_disc, "L": L, "w": w}


def run_phase_once(counts: Dict[str, int], runners: Dict[str, Runner], measured_ops: set[str], model_ms: Dict[str, float]) -> Tuple[float, float, float]:
    t0 = now_ns()
    for op in ORDER:
        if op in measured_ops:
            run = runners[op]
            for _ in range(counts[op]):
                run()
    measured_ms = (now_ns() - t0) / 1_000_000.0
    modeled_ms = sum(counts[op] * model_ms[op] for op in ORDER if op not in measured_ops)
    return measured_ms + modeled_ms, measured_ms, modeled_ms


def distribution(counts: Dict[str, int], runners: Dict[str, Runner], measured_ops: set[str], model_ms: Dict[str, float], reps: int) -> Tuple[Dict[str, float], Dict[str, float]]:
    run_phase_once(counts, runners, measured_ops, model_ms)
    totals = []
    measured = []
    for _ in range(reps):
        tot, meas, _const = run_phase_once(counts, runners, measured_ops, model_ms)
        totals.append(tot)
        measured.append(meas)
    s_tot = summarize(totals)
    s_meas = summarize(measured)
    s_tot["modeled_const_ms"] = sum(counts[op] * model_ms[op] for op in ORDER if op not in measured_ops)
    return s_tot, s_meas


def latex_escape(s: str) -> str:
    return s.replace("&", r"\&").replace("_", r"\_")


def write_outputs(outdir: Path, phases: Dict[str, Dict[str, int]], prim_stats: Dict[str, Dict[str, float]], results: Dict[str, Tuple[Dict[str, float], Dict[str, float]]], metadata: Dict[str, object]) -> None:
    outdir.mkdir(parents=True, exist_ok=True)

    op_latex = [
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r"Phase & $\mathbb{G}_1$ & $\mathbb{G}_2$ & $\mathbb{G}_T$ & pair. & $\bmod n^2$ & hash \\",
        r"\midrule",
    ]
    for name, c in phases.items():
        op_latex.append(latex_escape(name) + " & " + " & ".join(str(c[k]) for k in ORDER) + r" \\")
    op_latex += [r"\bottomrule", r"\end{tabular}"]
    (outdir / "perf_op_counts.tex").write_text("\n".join(op_latex) + "\n")

    prim_latex = [
        r"\begin{tabular}{lrrl}",
        r"\toprule",
        r"Primitive & Mean (ms) & Stdev (ms) & Backend \\",
        r"\midrule",
    ]
    for op in ORDER:
        s = prim_stats[op]
        prim_latex.append(f"{latex_escape(NICE[op])} & {s['mean']:.4f} & {s['stdev']:.4f} & {latex_escape(str(s['backend']))} " + r"\\")
    prim_latex += [r"\bottomrule", r"\end{tabular}"]
    (outdir / "perf_primitives.tex").write_text("\n".join(prim_latex) + "\n")

    timing_latex = [
        r"\begin{tabular}{lrrr}",
        r"\toprule",
        r"Phase & Mean (ms) & Stdev (ms) & Modeled const. (ms) \\",
        r"\midrule",
    ]
    for name, (s_tot, _s_meas) in results.items():
        timing_latex.append(
            f"{latex_escape(name)} & {s_tot['mean']:.1f} & {s_tot['stdev']:.2f} & {s_tot['modeled_const_ms']:.1f} " + r"\\"
        )
    g = results["Access proof: GENERATE (Dr B)"][0]
    v = results["Access proof: VERIFY (Gateway)"][0]
    timing_latex += [
        r"\midrule",
        rf"Access round-trip & {g['mean'] + v['mean']:.1f} & -- & {g['modeled_const_ms'] + v['modeled_const_ms']:.1f} \\",
        r"\bottomrule",
        r"\end{tabular}",
    ]
    (outdir / "perf_timings.tex").write_text("\n".join(timing_latex) + "\n")

    with (outdir / "perf_primitives.csv").open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["op", "name", "mean", "stdev", "median", "min", "max", "n", "backend", "native"])
        writer.writeheader()
        for op in ORDER:
            s = prim_stats[op]
            writer.writerow({"op": op, "name": NICE[op], **{k: s[k] for k in ["mean", "stdev", "median", "min", "max", "n"]}, "backend": s["backend"], "native": s["native"]})

    json_payload = {
        "metadata": metadata,
        "primitive_stats": prim_stats,
        "operation_counts": phases,
        "phase_results": {name: {"total": s_tot, "measured_part": s_meas} for name, (s_tot, s_meas) in results.items()},
    }
    (outdir / "perf_results.json").write_text(json.dumps(json_payload, indent=2, sort_keys=True) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=200, help="phase trials")
    ap.add_argument("--prim-reps", type=int, default=100, help="samples per primitive")
    ap.add_argument("--nbits", type=int, default=3072, help="bitlength of n for exp mod n^2")
    ap.add_argument("--pool", type=int, default=64, help="pool of pre-generated exponents/messages")
    ap.add_argument("--pairing-backend", choices=["auto", "petrelic", "py_ecc"], default="petrelic")
    ap.add_argument("--allow-model", action="store_true", help="permit modeled constants for primitives that cannot be measured")
    ap.add_argument("--require-native", action="store_true", help="fail unless gmpy2 and a native pairing backend are used")
    ap.add_argument("--outdir", default=".", help="directory for LaTeX/CSV/JSON output")
    args = ap.parse_args()

    if args.reps < 2 or args.prim_reps < 2:
        raise SystemExit("Use at least --reps 2 and --prim-reps 2")

    runners: Dict[str, Runner] = {}
    backend: Dict[str, str] = {}
    native: Dict[str, bool] = {}
    missing_errors = []

    try:
        runners["En2"], backend["En2"], native["En2"] = build_en2_runner(args.nbits, args.pool)
        runners["H"], backend["H"], native["H"] = build_hash_runner(args.pool)
    except Exception as e:
        missing_errors.append(f"failed to build En2/hash runners: {e}")

    try:
        pairing_runners, pairing_backend_labels, pairing_native = build_pairing_runners(args.pairing_backend, args.pool)
        runners.update(pairing_runners)
        backend.update(pairing_backend_labels)
        for op in ("E1", "E2", "ET", "P"):
            native[op] = pairing_native
    except Exception as e:
        missing_errors.append(str(e))

    available = set(runners.keys())
    missing_ops = [op for op in ORDER if op not in available]

    if args.require_native:
        not_native = [op for op in ORDER if op in native and not native[op]]
        if not_native:
            missing_errors.append("non-native backend for: " + ", ".join(not_native))

    if (missing_ops or missing_errors) and not args.allow_model:
        print("ERROR: not all primitives can be measured on this machine.", file=sys.stderr)
        if missing_ops:
            print("Missing primitives: " + ", ".join(missing_ops), file=sys.stderr)
        for e in missing_errors:
            print("- " + e, file=sys.stderr)
        print("\nFor paper-quality local measurements, install native backends and rerun:", file=sys.stderr)
        print("  python3 -m pip install gmpy2 petrelic", file=sys.stderr)
        print("  python3 op_costs_measured.py --reps 1000 --prim-reps 200 --require-native", file=sys.stderr)
        print("\nFor debugging only, rerun with --allow-model to reproduce the hybrid table.", file=sys.stderr)
        return 2

    measured_ops = set(ORDER) - set(missing_ops)
    model_ms = dict(MODELED_MS)

    # Per-primitive stats. If an op is missing and --allow-model was passed, insert the modeled constant visibly.
    batch_defaults = {"En2": 1, "H": 20000, "E1": 50, "E2": 20, "ET": 20, "P": 10}
    if any("py_ecc" in backend.get(op, "") for op in ("E1", "E2", "ET", "P")):
        batch_defaults.update({"E1": 3, "E2": 1, "ET": 3, "P": 1})

    prim_stats: Dict[str, Dict[str, float]] = {}
    for op in ORDER:
        if op in measured_ops:
            reps = max(30, args.prim_reps) if op != "H" else 30
            samples = time_primitive(runners[op], reps, batch_defaults[op])
            s = summarize(samples)
            s["backend"] = backend[op] 
            s["native"] = native.get(op, False) 
            s["modeled"] = False 
            prim_stats[op] = s
            model_ms[op] = s["mean"]
        else:
            prim_stats[op] = {
                "mean": MODELED_MS[op],
                "stdev": 0.0,
                "median": MODELED_MS[op],
                "min": MODELED_MS[op],
                "max": MODELED_MS[op],
                "q1": MODELED_MS[op],
                "q3": MODELED_MS[op],
                "n": 0,
                "backend": "MODELED FALLBACK",
                "native": False,
                "modeled": True,
            }

    phases, params = cost_model()
    online = [
        "Delegation: A sign",
        "Delegation: B verify",
        "Access proof: GENERATE (Dr B)",
        "Access proof: VERIFY (Gateway)",
    ]
    results: Dict[str, Tuple[Dict[str, float], Dict[str, float]]] = {}
    for name in online:
        results[name] = distribution(phases[name], runners, measured_ops, model_ms, args.reps)

    all_measured = len(measured_ops) == len(ORDER)
    all_native = all(native.get(op, False) for op in ORDER)

    metadata: Dict[str, object] = {
        "python": sys.version.replace("\n", " "),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "nbits": args.nbits,
        "reps": args.reps,
        "prim_reps": args.prim_reps,
        "params": params,
        "all_primitives_measured": all_measured,
        "all_primitives_native": all_native,
        "measured_ops": sorted(measured_ops),
        "missing_ops": missing_ops,
        "allow_model": args.allow_model,
    }

    print("=" * 96)
    print("CONSULT-SCOPED ACCESS PATH -- LOCAL OPERATION-COUNT MICROBENCHMARK")
    print(f"measured primitives: {', '.join(sorted(measured_ops)) if measured_ops else 'none'}")
    print(f"all primitives measured: {all_measured}; all primitives native/representative: {all_native}")
    print(f"platform: {metadata['platform']} | Python: {platform.python_version()} | |n|={args.nbits}")
    if not all_measured:
        print("WARNING: some primitives are MODELED. Do not claim full local measurement.")
    if not all_native:
        print("WARNING: at least one measured backend is not production-representative. Use --require-native for paper numbers.")
    print("=" * 96)

    print("\n(A) PER-PRIMITIVE timing [mean +/- stdev | median | min..max | n | backend]")
    for op in ORDER:
        s = prim_stats[op]
        marker = "MODELED" if s.get("modeled") else ("native" if s.get("native") else "measured/non-native")
        print(
            f"  {op:4s} {NICE[op]:12s} {s['mean']:10.4f} +/- {s['stdev']:8.4f} ms "
            f"| med {s['median']:10.4f} | {s['min']:8.4f}..{s['max']:8.4f} | n={int(s['n']):5d} | {marker} | {s['backend']}"
        )

    print("\nOperation counts per phase:")
    hdr = "  " + f"{'phase':35s}" + "".join(f"{NICE[k]:>14s}" for k in ORDER)
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for name, c in phases.items():
        print("  " + f"{name:35s}" + "".join(f"{c[k]:14d}" for k in ORDER))

    print(f"\n(B) PHASE distribution over R={args.reps} trials")
    for name in online:
        s_tot, s_meas = results[name]
        print(
            f"  {name:35s} {s_tot['mean']:9.2f} +/- {s_tot['stdev']:7.2f} ms "
            f"| med {s_tot['median']:9.2f} | [{s_tot['min']:.2f}, {s_tot['max']:.2f}] "
            f"| measured {s_meas['mean']:8.2f} + modeled {s_tot['modeled_const_ms']:7.2f}"
        )

    g = results["Access proof: GENERATE (Dr B)"][0]
    v = results["Access proof: VERIFY (Gateway)"][0]
    print("\nHEADLINE:")
    print(f"  generate:   {g['mean']:9.2f} +/- {g['stdev']:.2f} ms")
    print(f"  verify:     {v['mean']:9.2f} +/- {v['stdev']:.2f} ms")
    print(f"  round-trip: {g['mean'] + v['mean']:9.2f} ms")
    if all_measured:
        print("  claim status: all primitive operations in the operation-count model were measured locally.")
    else:
        print("  claim status: HYBRID measured+modeled; not suitable for a 'fully measured' claim.")

    outdir = Path(args.outdir)
    write_outputs(outdir, phases, prim_stats, results, metadata)
    print(f"\nWrote outputs to {outdir.resolve()}:")
    print("  perf_op_counts.tex, perf_primitives.tex, perf_timings.tex, perf_primitives.csv, perf_results.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
