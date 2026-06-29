# Consult-Scoped Anonymous-Credential Access-Path Microbenchmark

This repository contains the microbenchmark used for the performance evaluation of the consult-scoped anonymous-credential.

The benchmark measures the local cost of the primitive operations used by the paper's operation-count model and then executes the counted operations for the online phases of the access path. It is intended to support reproducible performance numbers for the paper.

## Scope

This code is an **operation-count microbenchmark**, not a full implementation of the complete DAC/NIZK protocol and not an end-to-end EHR/FHIR integration benchmark.

## What is measured

The script measures the following primitive operations:

| Symbol | Operation |
|---|---|
| `E1` | exponentiation/scalar multiplication in `G1` |
| `E2` | exponentiation/scalar multiplication in `G2` |
| `ET` | exponentiation in `GT` |
| `P` | pairing |
| `En2` | exponentiation modulo `n^2` for the Camenisch--Shoup-style escrow component |
| `H` | SHA-256 hash |

The benchmark then applies the paper's operation counts to the following phases:

- `Delegation: A sign`
- `Delegation: B verify`
- `Access proof: GENERATE (Dr B)`
- `Access proof: VERIFY (Gateway)`

The headline online access-path cost is:

```text
Access proof generation + gateway verification
```

## Paper parameters

The paper uses:

```text
k1 = 5
k2 = 5
L  = 2
w  = k1 + k2 + 3 = 13
```

These defaults are encoded in `cost_model()`.

## Recommended: run with Docker

Docker is recommended because the native pairing dependency (`petrelic`) is Linux-oriented.

### 1. Build the benchmark image

From the repository root:

```bash
docker build -t consult-ac-bench:py310 .
```

### 2. Run a quick smoke test

```bash
docker run --rm -it \
  -v "$PWD":/work \
  -w /work \
  consult-ac-bench:py310 \
  python op_costs_measured.py \
    --reps 20 \
    --prim-reps 10 \
    --require-native \
    --outdir results-smoke
```

The run should end with:

```text
claim status: all primitive operations in the operation-count model were measured locally.
```

If it does not, do not use the output as paper-quality measured results.

### 3. Run the paper-quality benchmark

```bash
docker run --rm -it \
  -v "$PWD":/work \
  -w /work \
  consult-ac-bench:py310 \
  python op_costs_measured.py \
    --reps 1000 \
    --prim-reps 200 \
    --require-native \
    --outdir results
```

This writes:

```text
results/
├── perf_op_counts.tex
├── perf_primitives.tex
├── perf_timings.tex
├── perf_primitives.csv
└── perf_results.json
```

Because the current directory is mounted with `-v "$PWD":/work`, the `results/` directory is written to the host machine.

## Dockerfile

Use the `Dockerfile` included in this repository. It installs:

- Python 3.10
- `gmpy2` / GMP for modulo-`n^2` exponentiations
- `petrelic` / RELIC for BLS-381 pairing operations
- `patchelf`, used to clear the executable-stack flag on the bundled RELIC shared library when necessary

## Native run without Docker

A native run may work on Linux with a compatible Python version:

```bash
python3 -m pip install gmpy2 petrelic

python3 op_costs_measured.py \
  --reps 1000 \
  --prim-reps 200 \
  --require-native \
  --outdir results
```

This is less portable than Docker. On macOS, `petrelic` may not install natively, so Docker is preferred.

## Optional modeled/debug mode

For debugging only:

```bash
python op_costs_measured.py \
  --reps 200 \
  --prim-reps 50 \
  --allow-model \
  --outdir results-debug
```

This allows missing primitives to be replaced by visible modeled constants. Results produced with `--allow-model` should not be described as fully locally measured.

## Troubleshooting

### `No module named 'petrelic'`

You are likely in a fresh Docker container where dependencies have not been installed, or you did not use the benchmark image. Build and run the image:

```bash
docker build -t consult-ac-bench:py310 .
docker run --rm -it -v "$PWD":/work -w /work consult-ac-bench:py310 bash
```

### `librelic... cannot enable executable stack`

The Dockerfile clears this flag automatically using `patchelf`. If running manually, use:

```bash
find /usr/local/lib/python3.10/site-packages \
  -name "librelic*.so" \
  -exec patchelf --clear-execstack {} \;
```

### Output files exist inside Docker but not on the host

Make sure Docker was launched with:

```bash
-v "$PWD":/work -w /work
```

Then write outputs somewhere under `/work`, for example:

```bash
--outdir results
```

If the container is still running, files can also be copied out with:

```bash
docker ps
docker cp <container_id>:/work/results ./results-from-container
```

## License


