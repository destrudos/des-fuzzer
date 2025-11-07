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

[...truncated for brevity - the entire markdown document continues encoded as percent encoding...]