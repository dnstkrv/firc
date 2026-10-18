#!/usr/bin/env python3
import statistics, sys

def per_gb(ticks, out):
    return round(ticks / (out / 1e9), 1)

def mbit(out, dt):
    return round(out * 8 / dt / 1e6, 1)

def parse(line):
    return dict(kv.split("=", 1) for kv in line.split())

def check(r):
    if r["mode"] not in ("A", "B"):
        raise ValueError(f"bad mode: {r}")
    if int(r["out"]) <= 0:
        raise ValueError(f"no bytes out: {r}")
    if min(int(r["busy"]), int(r["tv"]), int(r["fircd"])) < 0:
        raise ValueError(f"negative delta: {r}")

def summarize(rows):
    by = {}
    for r in rows:
        check(r)
        by.setdefault((r["case"], r["mode"]), []).append(r)
    out = {}
    for (case, mode), rs in by.items():
        out[(case, mode)] = {
            "busy_gb": statistics.median(per_gb(int(r["busy"]), int(r["out"])) for r in rs),
            "proc_gb": statistics.median(per_gb(int(r["tv"]) + int(r["fircd"]), int(r["out"])) for r in rs),
            "mbit": statistics.median(mbit(int(r["out"]), float(r["dt"])) for r in rs),
        }
    return out

def verdict(s, case):
    a, b = s[(case, "A")], s[(case, "B")]
    equal = abs(b["mbit"] - a["mbit"]) <= 0.1 * a["mbit"]
    if case == "wired":
        return equal and b["busy_gb"] < a["busy_gb"] and b["proc_gb"] < a["proc_gb"]
    return equal and b["busy_gb"] <= a["busy_gb"] and b["proc_gb"] <= a["proc_gb"]

def self_test():
    rows = [parse("case=wired mode=A round=1 busy=762 tv=70 fircd=5 out=178800000 dt=28"),
            parse("case=wired mode=B round=1 busy=551 tv=34 fircd=5 out=183500000 dt=28")]
    s = summarize(rows)
    assert s[("wired", "A")] == {"busy_gb": 4261.7, "proc_gb": 419.5, "mbit": 51.1}, s
    assert s[("wired", "B")] == {"busy_gb": 3002.7, "proc_gb": 212.5, "mbit": 52.4}, s
    assert verdict(s, "wired")
    tie = summarize([dict(r, case="lossy") for r in rows[:1]] + [dict(rows[0], case="lossy", mode="B")])
    assert verdict(tie, "lossy")
    assert not verdict(summarize([dict(r, case="wired") for r in rows[:1]] + [dict(rows[0], mode="B")]), "wired")
    a = rows[0]
    fast = summarize([a, dict(parse("case=wired mode=B round=1 busy=400 tv=34 fircd=5 out=250000000 dt=28"))])
    assert fast[("wired", "B")] == {"busy_gb": 1600.0, "proc_gb": 156.0, "mbit": 71.4}, fast
    assert not verdict(fast, "wired")
    dear = summarize([a, parse("case=wired mode=B round=1 busy=551 tv=90 fircd=5 out=183500000 dt=28")])
    assert dear[("wired", "B")]["busy_gb"] < dear[("wired", "A")]["busy_gb"]
    assert dear[("wired", "B")]["proc_gb"] == 517.7, dear
    assert not verdict(dear, "wired")
    for bad in ("mode=C", "out=0", "tv=-1", "fircd=-1"):
        k = bad.split("=")[0]
        row = dict(a, **{k: bad.split("=")[1]})
        try:
            summarize([row])
        except ValueError:
            continue
        raise AssertionError(bad)
    print("self-test ok")

if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
    else:
        s = summarize([parse(l) for l in sys.stdin if l.strip()])
        print("ticks per GB sent to the client (A sends ~13 % more per payload)")
        for (case, mode), v in sorted(s.items()):
            print(f"{case:10} {mode} busy/GB {v['busy_gb']:9.1f}  proc/GB {v['proc_gb']:8.1f}  {v['mbit']:6.1f} Mbit/s")
        for case in sorted({c for c, _ in s}):
            if (case, "A") in s and (case, "B") in s:
                print(f"{case:10} B<A: {'yes' if verdict(s, case) else 'no'}")
