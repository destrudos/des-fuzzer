#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
des'fuzzer
"""

import argparse
import base64
import importlib
import inspect
import io
import os
import random
import signal
import string
import sys
import time
import traceback
from dataclasses import dataclass
from multiprocessing import Pool, get_context
from typing import Callable, Dict, List, Optional, Set, Tuple, Union
from subprocess import Popen, PIPE, STDOUT


DEFAULT_POP = 64
DEFAULT_ELITE = 4
DEFAULT_GEN = 200
DEFAULT_MUT_PROB = 0.20
DEFAULT_CROSS_PROB = 0.70
DEFAULT_TOURN = 4
DEFAULT_MINLEN = 1
DEFAULT_MAXLEN = 256
DEFAULT_TIMEOUT = 0.5  # sekundy na eval
DEFAULT_WORKERS = max(1, os.cpu_count() or 1)


def rand_bytes(n: int) -> bytes:
    return os.urandom(n)

def clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))

def bmut_flip_bit(b: bytearray) -> None:
    if not b:
        return
    i = random.randrange(len(b))
    bit = 1 << random.randrange(8)
    b[i] ^= bit

def bmut_random_byte(b: bytearray) -> None:
    if not b:
        return
    i = random.randrange(len(b))
    b[i] = random.randrange(256)

def bmut_insert(b: bytearray, maxlen: int) -> None:
    if len(b) >= maxlen:
        return
    i = random.randrange(len(b)+1)
    b.insert(i, random.randrange(256))

def bmut_delete(b: bytearray, minlen: int) -> None:
    if len(b) <= minlen:
        return
    i = random.randrange(len(b))
    del b[i]

def bmut_splice(a: bytes, b: bytes) -> bytes:
    if not a or not b:
        return a if random.random()<0.5 else b
    i = random.randrange(1, len(a))
    j = random.randrange(1, len(b))
    return a[:i] + b[j:]

def pretty_bytes(b: bytes, limit: int = 64) -> str:
    if len(b) <= limit:
        s = base64.b64encode(b).decode()
    else:
        s = base64.b64encode(b[:limit]).decode() + "...(trunc)"
    return f"{len(b)}B b64={s}"

class CoverageTracer:
    """Prosty tracer linii z sys.settrace."""
    def __init__(self):
        self.lines: Set[Tuple[str, int]] = set()

    def _tr(self, frame, event, arg):
        if event == "line":
            code = frame.f_code
            self.lines.add((code.co_filename, frame.f_lineno))
        return self._tr

    def run_with_coverage(self, fn: Callable[[bytes], None], data: bytes, timeout: float) -> Tuple[Set[Tuple[str,int]], Optional[Exception], Optional[str]]:
        """Uruchamia fn(data) z pomiarem pokrycia i timeoutem."""
        start = time.time()
        exc: Optional[Exception] = None
        exc_tb: Optional[str] = None
        tracer = self

        def handler(signum, frame):
            raise TimeoutError("execution timed out")

        can_alarm = hasattr(signal, "SIGALRM")
        old = None
        if can_alarm:
            old = signal.signal(signal.SIGALRM, handler)
            signal.setitimer(signal.ITIMER_REAL, timeout)

        sys.settrace(tracer._tr)
        try:
            fn(data)
        except Exception as e:
            exc = e
            buf = io.StringIO()
            traceback.print_exc(file=buf)
            exc_tb = buf.getvalue()
        finally:
            sys.settrace(None)
            if can_alarm:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
                if old is not None:
                    signal.signal(signal.SIGALRM, old)

    
        if not can_alarm and (time.time() - start) > timeout and exc is None:
            exc = TimeoutError("soft timeout exceeded")
            exc_tb = None

        return set(tracer.lines), exc, exc_tb


@dataclass
class EvalResult:
    data: bytes
    fitness: float
    new_cov: int
    total_cov: int
    crashed: bool
    exception_msg: Optional[str]
    coverage_key: frozenset 

# ---- pyfunc ----

def _load_callable(dotted: str) -> Callable[[bytes], None]:
    """
    Importuje funkcję przyjmującą bytes: module:qualname (np. mypkg.mod:handler)
    """
    if ":" not in dotted:
        raise ValueError("Oczekiwano formatu module:qualname")
    modname, qual = dotted.split(":", 1)
    mod = importlib.import_module(modname)
    obj = mod
    for part in qual.split("."):
        obj = getattr(obj, part)
    if not callable(obj):
        raise TypeError("Załadowany obiekt nie jest wywoływalny")
    sig = inspect.signature(obj)
    if len(sig.parameters) != 1:
        print("[WARN] Funkcja nie ma jednego parametru – zakładam obj(data: bytes).")
    return obj  

def eval_pyfunc_individual(args) -> EvalResult:
    (target_str, data, base_cov_key, timeout) = args
    fn = _load_callable(target_str)
    tracer = CoverageTracer()
    lines_before = set(tracer.lines)
    lines, exc, _tb = tracer.run_with_coverage(fn, data, timeout)
    cov_key = frozenset(lines)
    new_cov = len(lines - set(base_cov_key))
    total_cov = len(lines)
    crashed = exc is not None
    bonus = 5.0 if crashed else 0.0
    fitness = float(new_cov) + bonus
    return EvalResult(
        data=data,
        fitness=fitness,
        new_cov=new_cov,
        total_cov=total_cov,
        crashed=crashed,
        exception_msg=(repr(exc) if exc else None),
        coverage_key=cov_key,
    )

def run_proc(cmd_template: List[str], data: bytes, timeout: float) -> Tuple[int, str]:
    """
    Uruchamia proces, podstawiając payload do STDIN.
    Zwraca (returncode, output_text_do_limitu).
    """
    try:
        p = Popen(cmd_template, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
        out, _ = p.communicate(input=data, timeout=timeout)
        return p.returncode, out.decode(errors="replace")[:4096]
    except Exception as e:
        return 9999, f"[runner-exc] {e}"

def eval_proc_individual(args) -> EvalResult:
    (cmd, data, _base_cov_key, timeout) = args
    rc, out = run_proc(cmd, data, timeout)
    crashed = (rc < 0) or (rc in (134, 139, 132, 133)) or ("AddressSanitizer" in out) or ("panic" in out.lower())  # heurystyka
 
    fitness = 1.0 if crashed else 0.0
    return EvalResult(
        data=data,
        fitness=fitness,
        new_cov=0,
        total_cov=0,
        crashed=crashed,
        exception_msg=f"rc={rc}",
        coverage_key=frozenset(),  
    )

# ---------- GA ----------

@dataclass
class GAConfig:
    pop_size: int
    elite: int
    generations: int
    mut_prob: float
    cross_prob: float
    tourn_k: int
    min_len: int
    max_len: int
    timeout: float
    workers: int

class GAFuzzer:
    def __init__(self,
                 mode: str,
                 target: Union[str, List[str]],
                 cfg: GAConfig,
                 seed_inputs: Optional[List[bytes]] = None):
        assert mode in ("pyfunc", "proc")
        self.mode = mode
        self.target = target
        self.cfg = cfg
        self.population: List[bytes] = []
        self.global_coverage: Set[Tuple[str,int]] = set()  
        self.corpus: List[bytes] = []  
        if seed_inputs:
            self.population.extend(seed_inputs)
        while len(self.population) < self.cfg.pop_size:
            ln = random.randint(self.cfg.min_len, self.cfg.max_len)
            self.population.append(rand_bytes(ln))
        self.best: Optional[EvalResult] = None

    def _evaluate(self, pop: List[bytes]) -> List[EvalResult]:
        base_cov_key = frozenset(self.global_coverage)
        tasks = []
        if self.mode == "pyfunc":
            for x in pop:
                tasks.append((self.target, x, base_cov_key, self.cfg.timeout))
            worker = eval_pyfunc_individual
        else:
            cmd = self.target  # type: ignore
            for x in pop:
                tasks.append((cmd, x, base_cov_key, self.cfg.timeout))
            worker = eval_proc_individual

        with get_context("spawn").Pool(processes=self.cfg.workers) as pool:
            results = pool.map(worker, tasks)
        return results

    def _select_parent(self, evaluated: List[EvalResult]) -> EvalResult:
        k = self.cfg.tourn_k
        cand = random.sample(evaluated, k=k)
        return max(cand, key=lambda e: e.fitness)

    def _crossover(self, a: bytes, b: bytes) -> bytes:
        if random.random() > self.cfg.cross_prob:
            return a if random.random() < 0.5 else b
        child = bmut_splice(a, b)
        return child[: self.cfg.max_len]

    def _mutate(self, data: bytes) -> bytes:
        if random.random() > self.cfg.mut_prob:
            return data
        ba = bytearray(data)
        ops = [bmut_flip_bit, bmut_random_byte, lambda bb: bmut_insert(bb, self.cfg.max_len), lambda bb: bmut_delete(bb, self.cfg.min_len)]
        for _ in range(random.randint(1, 3)):
            random.choice(ops)(ba)
        if len(ba) > self.cfg.max_len:
            del ba[self.cfg.max_len:]
        if len(ba) < self.cfg.min_len:
            ba.extend(rand_bytes(self.cfg.min_len - len(ba)))
        return bytes(ba)

    def run(self):
        for gen in range(1, self.cfg.generations + 1):
            evaluated = self._evaluate(self.population)

            gen_best = max(evaluated, key=lambda e: e.fitness)
            if (self.best is None) or (gen_best.fitness > self.best.fitness):
                self.best = gen_best

            if self.mode == "pyfunc":
                added = 0
                for ev in evaluated:
                    before = len(self.global_coverage)
                    self.global_coverage |= set(ev.coverage_key)
                    if len(self.global_coverage) > before:
                        self.corpus.append(ev.data)
                        added += 1

                self.corpus = sorted(set(self.corpus), key=len)[:512]
            else:
           
                crashes = [ev.data for ev in evaluated if ev.crashed]
                if crashes:
                    self.corpus.extend(crashes)
                    self.corpus = self.corpus[-512:]

            # L
            if gen % 5 == 0 or gen == 1:
                if self.mode == "pyfunc":
                    print(f"[GEN {gen}] best_fit={self.best.fitness:.2f} newcov={gen_best.new_cov} totalcov={len(self.global_coverage)} data={pretty_bytes(self.best.data)} crashed={self.best.crashed}")
                else:
                    print(f"[GEN {gen}] best_fit={self.best.fitness:.2f} crashed={self.best.crashed} data={pretty_bytes(self.best.data)}")

            # Selekcja elit
            evaluated.sort(key=lambda e: e.fitness, reverse=True)
            elites = [e.data for e in evaluated[: self.cfg.elite]]

            # Selekcja rodziców i tworzenie potomstwa
            next_pop: List[bytes] = elites.copy()
            while len(next_pop) < self.cfg.pop_size:
                p1 = self._select_parent(evaluated).data
                p2 = self._select_parent(evaluated).data
                child = self._crossover(p1, p2)
                child = self._mutate(child)
                next_pop.append(child)

            # Dolewaj corpus-owe rozruszniki co jakiś czas
            if self.corpus and gen % 7 == 0:
                seeds = random.sample(self.corpus, k=min(len(self.corpus), self.cfg.pop_size // 8))
                # lekko zmutuj
                seeds = [self._mutate(s) for s in seeds]
                # wymień losowe ogony populacji
                for i, s in enumerate(seeds):
                    idx = -1 - i
                    next_pop[idx] = s

            self.population = next_pop

        # Koniec – podsumowanie
        print("\n=== SUMMARY ===")
        if self.mode == "pyfunc":
            print(f"Global coverage lines: {len(self.global_coverage)}")
        if self.best:
            print(f"Best fitness: {self.best.fitness:.2f}")
            print(f"Best crashed: {self.best.crashed}  info: {self.best.exception_msg}")
            print(f"Best input: {pretty_bytes(self.best.data)}")
            # Zapisz najlepszy przypadek testowy
            with open("best_input.bin", "wb") as f:
                f.write(self.best.data)
            print("Saved best_input.bin")


def demo_target(payload: bytes) -> None:
    """
    Przykładowa funkcja do fuzzowania.
    - Dekoduje base64, potem interpretuje jako ascii i przechodzi przez kilka gałęzi.
    """
    s = payload.decode('latin1', errors='ignore')


    try:
        if all(c in (string.ascii_letters + string.digits + "+/=\n\r") for c in s[:40]):
            raw = base64.b64decode(s, validate=False)
        else:
            raw = payload
    except Exception:
        raw = payload


    if raw.startswith(b"PK\x03\x04"):  # zip

        if b"evil" in raw:
            raise ValueError("ZIP structure error")
    elif raw.startswith(b"\x89PNG\r\n\x1a\n"):  # png
        if b"IHDR" in raw and raw.count(b"\x00") > 10:
            raise RuntimeError("PNG crash-like")
    elif raw.startswith(b"%PDF"):
        if b"/ObjStm" in raw:
            _ = 1/0  # ZeroDivisionError
    else:

        if len(raw) > 50 and raw[0] == 0 and raw[-1] == 255:
            if b"CRASH" in raw:
                raise AssertionError("sentinel matched")
        if raw.count(b"A") > 10 and b"XYZ" in raw:
            _ = [][0]  # IndexError

# ---------- CLI ----------

def parse_args():
    p = argparse.ArgumentParser(description="GA-based fuzzer")
    sub = p.add_subparsers(dest="mode", required=True)

    p_py = sub.add_parser("pyfunc", help="fuzzuj funkcję Pythona z pokryciem")
    p_py.add_argument("--target", required=False, default="__main__:demo_target",
                      help="module:qualname funkcji (domyślnie: __main__:demo_target)")
    p_py.add_argument("--seed", action="append", default=[],
                      help="ścieżka do pliku seed (można podać wiele)")

    p_pr = sub.add_parser("proc", help="fuzzuj proces (bez pokrycia)")
    p_pr.add_argument("--cmd", nargs="+", required=True,
                      help="komenda procesu; payload idzie na STDIN")

    for sp in (p_py, p_pr):
        sp.add_argument("--pop", type=int, default=DEFAULT_POP)
        sp.add_argument("--elite", type=int, default=DEFAULT_ELITE)
        sp.add_argument("--gen", type=int, default=DEFAULT_GEN)
        sp.add_argument("--mut", type=float, default=DEFAULT_MUT_PROB)
        sp.add_argument("--cross", type=float, default=DEFAULT_CROSS_PROB)
        sp.add_argument("--tourn", type=int, default=DEFAULT_TOURN)
        sp.add_argument("--minlen", type=int, default=DEFAULT_MINLEN)
        sp.add_argument("--maxlen", type=int, default=DEFAULT_MAXLEN)
        sp.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
        sp.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    return p.parse_args()

def load_seeds(paths: List[str], minlen: int, maxlen: int) -> List[bytes]:
    out = []
    for pth in paths:
        try:
            with open(pth, "rb") as f:
                data = f.read()
                data = data[:maxlen]
                if len(data) < minlen:
                    data += rand_bytes(minlen - len(data))
                out.append(data)
        except Exception as e:
            print(f"[seed warn] {pth}: {e}")
    return out

def main():
    args = parse_args()
    cfg = GAConfig(
        pop_size=args.pop,
        elite=args.elite,
        generations=args.gen,
        mut_prob=args.mut,
        cross_prob=args.cross,
        tourn_k=args.tourn,
        min_len=args.minlen,
        max_len=args.maxlen,
        timeout=args.timeout,
        workers=args.workers,
    )

    if args.mode == "pyfunc":
        seeds = load_seeds(args.seed, cfg.min_len, cfg.max_len) if args.seed else None
        fz = GAFuzzer(
            mode="pyfunc",
            target=args.target,
            cfg=cfg,
            seed_inputs=seeds,
        )
    else:
        fz = GAFuzzer(
            mode="proc",
            target=args.cmd,
            cfg=cfg,
            seed_inputs=None,
        )

    print("[*] Start fuzzingu:", vars(cfg))
    if args.mode == "pyfunc":
        print(f"[*] Target (pyfunc): {args.target}")
    else:
        print(f"[*] Target (proc): {' '.join(args.cmd)}")
    fz.run()

if __name__ == "__main__":
    main()
