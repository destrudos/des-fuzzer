# Des'fuzzer — Genetic-Algorithm Fuzzing for Python Functions and External Processes

A single-file, coverage-guided genetic fuzzer with two execution modes:

- **`pyfunc`**: fuzz a Python callable (`module:qualname`) with lightweight line-coverage via `sys.settrace`. Fitness rewards new coverage + exception bonus.
- **`proc`**: fuzz an external process (payload on `STDIN`) with crash-leaning fitness (return-code/signature heuristics), no coverage.

The fuzzer implements tournament selection, single-point splicing crossover, multiple byte-level mutation operators, elitism, a deduplicated interesting corpus, parallel evaluation via `multiprocessing` (spawn), per-test timeouts, and a small CLI. At the end of a run it writes the best input to `best_input.bin`.

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Fuzz a Python function (`pyfunc`)](#fuzz-a-python-function-pyfunc)
  - [Fuzz an external process (`proc`)](#fuzz-an-external-process-proc)
- [CLI Reference](#cli-reference)
- [Target Interface](#target-interface)
  - [Python function target](#python-function-target)
  - [External process target](#external-process-target)
- [Architecture](#architecture)
- [Coverage and Fitness](#coverage-and-fitness)
  - [`pyfunc` coverage model](#pyfunc-coverage-model)
  - [`proc` crash heuristics](#proc-crash-heuristics)
- [Genetic Operators](#genetic-operators)
- [Corpus Management](#corpus-management)
- [Timeouts and Platform Notes](#timeouts-and-platform-notes)
- [Performance Tuning](#performance-tuning)
- [Reproducibility](#reproducibility)
- [Extending the Fuzzer](#extending-the-fuzzer)
- [Limitations](#limitations)
- [Security Considerations](#security-considerations)
- [Output Artifacts](#output-artifacts)
- [License](#license)

---

## Features

- Coverage-guided GA fuzzing for Python callables (line coverage) and external binaries (crash-biased).
- Parallel evaluation (`multiprocessing` with `spawn`) for deterministic worker lifecycle.
- Tournament selection, elitism, splicing crossover, and multi-op mutation.
- Interesting corpus injection (AFL-style): add inputs that increase coverage (pyfunc) or crash (proc).
- Hard (POSIX `SIGALRM`) or soft (wall-clock) timeouts per test case.
- Minimal dependencies, single file, MIT license.

---

## Requirements

- Python 3.8+.
- POSIX for hard timeouts (`SIGALRM`). On Windows, a soft timeout is used automatically.
- No third-party packages required.

---

## Installation

This project is single-file. Save the provided source as:

```
ga_fuzzer.py
```

Optionally make it executable:

```bash
chmod +x ga_fuzzer.py
```

---

## Quick Start

### Fuzz a Python function (`pyfunc`)

Run the demo target (bundled):

```bash
python ga_fuzzer.py pyfunc --gen 100 --pop 64 --workers 4
```

Fuzz your own function:

1. Create `my_mod.py`:

   ```python
   # my_mod.py
   def handle(data: bytes) -> None:
      # Replace with real parser/logic
      if data.startswith(b"PK\x03\x04") and b"evil" in data:
        raise ValueError("ZIP structure error")
   ```

2. Run the fuzzer:

   ```bash
   python ga_fuzzer.py pyfunc --target my_mod:handle --gen 200 --pop 128 --workers 8
   ```

Seed with initial inputs (repeatable flag):

```bash
python ga_fuzzer.py pyfunc --target my_mod:handle \
  --seed seeds/zip.bin --seed seeds/png.bin --seed seeds/pdf.bin
```

### Fuzz an external process (`proc`)

The fuzzer writes each candidate to the process STDIN and collects combined output:

```bash
python ga_fuzzer.py proc --cmd ./parse_pdf --gen 200 --pop 128 --workers 8
```

With Python interpreter:

```bash
python ga_fuzzer.py proc --cmd python ./my_parser.py --gen 100
```

---

## CLI Reference

Common options exist under both subcommands.

```
pyfunc mode:
  python ga_fuzzer.py pyfunc [--target MOD:QUAL] [--seed PATH ...]
                  [--pop N] [--elite N] [--gen N]
                  [--mut P] [--cross P] [--tourn K]
                  [--minlen N] [--maxlen N]
                  [--timeout SEC] [--workers N]

proc mode:
  python ga_fuzzer.py proc  --cmd CMD [CMD ...]
                  [--pop N] [--elite N] [--gen N]
                  [--mut P] [--cross P] [--tourn K]
                  [--minlen N] [--maxlen N]
                  [--timeout SEC] [--workers N]
```

Parameters:

- `--target` (`pyfunc`): Python callable in `module:qualname` form. Default: `__main__:demo_target`.
- `--seed` (`pyfunc`): one or more seed file paths. May repeat.
- `--cmd` (`proc`): command vector to exec; the payload goes to `STDIN`.
- `--pop`: population size. Default: 64.
- `--elite`: elitism count per generation. Default: 4.
- `--gen`: number of generations. Default: 200.
- `--mut`: mutation probability per child (0–1). Default: 0.20.
- `--cross`: crossover probability per child (0–1). Default: 0.70.
- `--tourn`: tournament size `K`. Default: 4.
- `--minlen` / `--maxlen`: genome length bounds in bytes. Defaults: 1 / 256.
- `--timeout`: per-test timeout (seconds). Default: 0.5.
- `--workers`: parallel worker processes. Default: CPU count.

---

## Target Interface

### Python function target

- Signature: **`def fn(data: bytes) -> None`** (one parameter recommended).
- The fuzzer imports the function using `importlib` from `module:qualname`.
- Coverage is collected for executed Python lines using `sys.settrace`.

Notes:
- If the function raises an exception, the test is considered a crash for bonus fitness, and traceback is recorded for logging.
- Only pure Python code contributes to line coverage; C extensions are not visible to `sys.settrace`.

### External process target

- Provide a command vector via `--cmd ...`.
- Each candidate input is piped to `STDIN`.
- Combined `STDOUT+STDERR` is captured (capped at 4096 bytes for heuristics).
- Fitness prefers crash-like behavior; see [proc crash heuristics](#proc-crash-heuristics).

---

## Architecture

```
+---------------------+
| Initial Population  |  <-- random bytes and optional seeds
+----------+----------+
            |
            v
    +-------+--------+    evaluate() in parallel (Pool/spawn)
    |  Evaluation   |  ---> fitness, coverage, crash flag
    +-------+--------+
          |
          +--> Update Global Coverage (pyfunc)
          +--> Update Corpus (new coverage/crashes)
          |
          v
    +-------+--------+
    |  Selection    |  tournament(K), elitism(E)
    +-------+--------+
          |
          v
    +-------+--------+
    |  Variation    |  crossover(splice), mutation(multi-op)
    +-------+--------+
          |
          v
    +-------+--------+
    | Next Generation|
    +----------------+
```

- Elitism: top `E` individuals pass unchanged.
- Corpus injection: every 7th generation, a subset of corpus entries (mutated) replaces tail individuals.

---

## Coverage and Fitness

### `pyfunc` coverage model

- Coverage unit: `(filename, line_number)` collected by a tracer on "line" events.
- Global coverage: set of lines seen across all tests so far.
- Per-test fitness = `new_covered_lines_vs_global + bonus_exception`.
  - `bonus_exception` = `+5.0` if the target raised any exception.
- Corpus add: inputs that increase the global coverage are stored (size-bounded, dedup by bytes/length heuristic).

Caveats:
- `sys.settrace` is low-overhead but still slower than native code instrumentation.
- Coverage does not include executed C code paths.

### `proc` crash heuristics

- A test case is considered crash-like if any of:
  - return code < 0 (killed by signal),
  - return code in {134, 139, 132, 133} (common abort/SEGV/ILL traps),
  - output contains substrings `AddressSanitizer` (ASan) or `panic`.
- Per-test fitness = `1.0` if crash-like; else `0.0`.
- Corpus add: crash-like inputs are retained (size-bounded).

These are heuristics; tune for your target as needed.

---

## Genetic Operators

- Genome: raw byte string `bytes`, length constrained to [minlen, maxlen].
- Crossover: single-point splice between two parents (random cut positions). Applied with probability `--cross`.
- Mutation (applied with probability `--mut`):
  - Flip one random bit in a random byte.
  - Replace a random byte with a random value.
  - Insert a random byte at a random position (if `< maxlen`).
  - Delete a random byte (if `> minlen`).
  - 1–3 of the above are applied per mutation event.
- Length constraints are enforced post-mutation.

Selection: tournament of size `--tourn`, choose the fittest.

---

## Corpus Management

- `pyfunc`: add any input that increases the global coverage set.
- `proc`: add any input that triggers crash-like behavior.
- Corpus is deduplicated (by bytes) and truncated to 512 entries.
- Every 7th generation: sample up to `pop_size/8` corpus entries, mutate them, and replace the tail of the new population to inject diversity.

---

## Timeouts and Platform Notes

- POSIX: hard timeout via `SIGALRM` (`setitimer(ITIMER_REAL)`) around the traced call.
- Windows or non-ALRM env: soft timeout via wall-clock check; if elapsed time exceeds `--timeout`, a `TimeoutError` is recorded.
- Each evaluation runs in a worker process created via `spawn` (works across platforms; avoids `fork`-with-threads pitfalls).

Implications:
- Targets that block on I/O may require larger `--timeout` or sandboxing.
- For `proc` mode, the child process is terminated by `Popen.communicate(timeout=...)`.

---

## Performance Tuning

- Increase `--workers` up to CPU count for throughput.
- Use moderate `--timeout` (e.g., 0.1–0.5 s) to avoid head-of-line blocking.
- Seed with known-good files to reduce warm-up.
- Narrow `--maxlen` initially (e.g., 128) and expand later if needed.
- For `pyfunc`, keep target code in Python to benefit from the tracer; deep C extensions will not expose coverage.
- If evaluation is CPU-light, prefer larger populations (`--pop 128..512`) to exploit parallelism.

Reproducibility

The current CLI does not expose a PRNG seed. For deterministic runs, add at program start:

```python
import random, os
random.seed(12345)
os.environ["PYTHONHASHSEED"] = "0"
```

Determinism is still affected by multiprocessing scheduling and non-deterministic target behavior. Use single worker (`--workers 1`) to minimize nondeterminism during debugging.

---

## Extending the Fuzzer

- Mutation dictionary: add structured tokens (file headers, magic values) and block-level duplication.
- Coverage backends: swap `sys.settrace` for `coverage.py` or bytecode-level tracing to collect branch/decision coverage.
- Fitness shaping: implement distance-to-target (e.g., parse error locality, branch hints).
- Persistent mode: cache target import and keep stateful executors alive between evaluations for lower overhead.
- Crash triage: integrate better crash deduplication (stack hashing) and automatic minimization (e.g., delta debugging).

---

## Limitations

- Line coverage only; no basic-block or edge coverage out of the box.
- C extensions are opaque to `sys.settrace`.
- No integrated input minimizer; you can post-process `best_input.bin`.
- `_load_callable` runs in worker eval; importing per test incurs overhead on some targets.
- Soft timeouts on Windows do not preempt CPU-bound loops inside the target.

---

## Security Considerations

- Fuzzing untrusted code is risky. Run targets inside a container/VM with strict resource limits and no network access.
- For `proc` mode, ensure the binary cannot escape via environment variables or file system side-effects; use chroots/containers.

---

## Output Artifacts

- `best_input.bin`: the globally best individual by fitness (written at the end).
- Console log: per 5 generations (and on generation 1), prints summary with coverage/crash info and a Base64 preview of the payload head.

---

## License

MIT. 
