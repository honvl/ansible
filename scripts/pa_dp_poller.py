#!/usr/bin/env python3
"""Capture per-second PAN-OS dataplane evidence around short packet-buffer / session-setup freezes.

The freezes last about 5 s, so one-minute counters and tech support files cannot show them. Two things make them visible:

* 'show running resource-monitor second last 60' returns the previous 60 s of per-core CPU, packet buffer and packet
  descriptor use in ONE call. A fetch every <60 s therefore rebuilds a gap-free per-second history, and it does not
  matter exactly when a job starts: startup lag only delays the fetch, it does not lose data.
* Point probes every few seconds ('show clock', 'show session info', 'ingress-backlogs') record their response time. A slow
  'show clock' means the management plane stalled; a slow or zero-rate 'show session info' with a fast 'show clock'
  means the dataplane stalled.

Both firewalls are polled directly and in parallel; there is no HA-active detection step.

Credentials come from the environment only (never argv): PANOS_API_KEY, or PANOS_USERNAME + PANOS_PASSWORD.
Standard library only, so it runs in any execution environment.

  pa_dp_poller.py --fw 10.204.9.20 --fw 10.204.10.20 --out /tmp/pa_poll --duration 660
  pa_dp_poller.py --fw 10.204.9.20 --once        # one cycle, prints what it parsed (use this to verify a new firewall)

Per-second timestamps are estimated from the fetch time and are good to about +-2 s.
"""
import argparse
import collections
import concurrent.futures
import datetime as dt
import gzip
import json
import os
import re
import signal
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

SECOND_CMD = "<show><running><resource-monitor><second><last>60</last></second></resource-monitor></running></show>"
SESSION_CMD = "<show><session><info/></session></show>"
CLOCK_CMD = "<show><clock/></show>"
BACKLOG_CMD = "<show><running><resource-monitor><ingress-backlogs/></resource-monitor></running></show>"
COUNTER_CMD = "<show><counter><global/></counter></show>"

# counters worth diffing around an event (name regex)
COUNTER_RE = re.compile(
    r"^(log_.*(loss|fail|full)|pkt_sent_host_drop|pkt_alloc_failure|ctd_dns_(wait|reply|mp|req_lookup|benign|malicious|cache)\w*|"
    r"session_(allocated|installed|install_error\w*)|ctd_exceed_queue_limit|ctd_wif_raw_throttle|tcp_exceed_flow_seg_limit|"
    r"flow_dos_drop\w*|fbo_pkt\w*)$")


class PanError(Exception):
    pass


def now():
    return time.time()


def stamp(t=None):
    return dt.datetime.fromtimestamp(t if t is not None else now()).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------------------------------------------------
# XML API client
# ---------------------------------------------------------------------------------------------------------------------
class Fw:
    def __init__(self, host, key="", user="", password="", verify=False, timeout=6.0, scheme="https"):
        self.host, self.key, self.user, self.password = host, key, user, password
        self.timeout, self.scheme = timeout, scheme
        self.ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()

    def _post(self, data, timeout):
        req = urllib.request.Request(f"{self.scheme}://{self.host}/api/", data=urllib.parse.urlencode(data).encode())
        if self.key:
            req.add_header("X-PAN-KEY", self.key)  # header, so the key never appears in a URL or a log line
        with urllib.request.urlopen(req, timeout=timeout, context=self.ctx) as r:
            return r.read()

    def login(self):
        if self.key:
            return
        root = ET.fromstring(self._post({"type": "keygen", "user": self.user, "password": self.password}, 15))
        self.key = root.findtext(".//key") or ""
        if not self.key:
            raise PanError(f"{self.host}: keygen failed")

    def op(self, cmd, timeout=None):
        """-> (xml root, raw text, round-trip ms). Raises on HTTP error, timeout or non-success status."""
        t0 = time.monotonic()
        raw = self._post({"type": "op", "cmd": cmd}, timeout or self.timeout)
        rtt = (time.monotonic() - t0) * 1000.0
        root = ET.fromstring(raw)
        if root.get("status") not in (None, "success"):
            raise PanError(f"{self.host}: {cmd[:40]} -> status {root.get('status')}")
        return root, raw.decode("utf-8", "replace"), rtt


# ---------------------------------------------------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------------------------------------------------
def _ints(s):
    return [int(x) if x.isdigit() else None for x in re.split(r"[,\s]+", s.strip()) if x]


def parse_second_text(text):
    """CLI text form of 'show running resource-monitor second': newest row first, '*' = not a dataplane core."""
    lines = text.splitlines()
    cores, util = {}, {}
    i = next((k for k, ln in enumerate(lines) if ln.startswith("CPU load (%) during last 60 seconds")), None)
    if i is not None and i + 1 < len(lines) and lines[i + 1].split()[:1] == ["core"]:
        ids = [int(x) for x in lines[i + 1].split()[1:]]
        rows = []
        for ln in lines[i + 2:]:
            toks = ln.split()
            if not toks or not all(t == "*" or t.isdigit() for t in toks):
                break
            rows.append(toks)
        for j, cid in enumerate(ids):
            col = [r[j] if j < len(r) else "*" for r in rows]
            if any(c != "*" for c in col):
                cores[cid] = [int(c) if c != "*" else None for c in col]
    j = next((k for k, ln in enumerate(lines) if ln.startswith("Resource utilization (%) during last 60 seconds")), None)
    if j is not None:
        name = None
        for ln in lines[j + 1:]:
            s = ln.strip()
            if s.startswith(("Resource monitoring", "CPU load")):
                break  # next report block
            if s.endswith(":"):
                name = s[:-1]
                util[name] = []
            elif s and re.fullmatch(r"[\d\s]+", s) and name:
                util[name] += [int(x) for x in s.split()]
            elif s and name and util.get(name):
                break  # next report section
    return {"cores": cores, "util": util, "fmt": "text"}


def parse_second(root):
    """Structured XML (cpu-load-maximum / resource-utilization entries) or, failing that, the CLI text blob in <result>."""
    cores, util = {}, {}
    src = root.find(".//cpu-load-maximum")
    if src is None:
        src = root.find(".//cpu-load-average")
    if src is not None:
        for e in src.findall("entry"):
            cid, val = e.findtext("coreid"), e.findtext("value")
            if cid is not None and cid.strip().isdigit() and val:
                cores[int(cid)] = _ints(val)
        ru = root.find(".//resource-utilization")
        if ru is not None:
            for e in ru.findall("entry"):
                n, v = e.findtext("name"), e.findtext("value")
                if n and v:
                    util[n.strip()] = _ints(v)
        if cores:
            return {"cores": cores, "util": util, "fmt": "xml"}
    res = root.find(".//result")
    return parse_second_text("".join(res.itertext()) if res is not None else "")


def parse_session(root):
    d = {}
    for k in ("num-active", "num-max", "pps", "cps", "kbps", "num-tcp", "num-udp", "num-icmp"):
        v = root.findtext(f".//{k}")
        if v is not None and re.fullmatch(r"\s*-?\d+\s*", v):
            d[k.replace("-", "_")] = int(v)
    return d


def parse_counters(root):
    out = {}
    for e in root.iter("entry"):
        n = e.findtext("name")
        if n and COUNTER_RE.match(n):
            try:
                out[n] = int(e.findtext("value") or 0)
            except ValueError:
                pass
    return out


def per_second_rows(parsed, fetched_at):
    """Newest-first lists -> one dict per second. t = estimated wall-clock second (+-2 s)."""
    cores, util = parsed["cores"], parsed["util"]
    n = max((len(v) for v in cores.values()), default=0)

    def at(name, i):
        v = util.get(name) or []
        return v[i] if i < len(v) else None

    rows = []
    for i in range(n):
        vals = {c: v[i] for c, v in cores.items() if i < len(v) and v[i] is not None}
        hot = sorted(c for c, x in vals.items() if x >= 99)
        rows.append({"t": int(fetched_at) - 1 - i, "buf": at("packet buffer", i), "desc": at("packet descriptor", i),
                     "tags": at("sw tags descriptor", i), "n99": len(hot), "hot": hot,
                     "max": max(vals.values(), default=None),
                     "mean": round(sum(vals.values()) / len(vals), 1) if vals else None})
    return rows


# ---------------------------------------------------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------------------------------------------------
def detect_seconds(rows, a):
    out = []
    for r in rows:
        why = []
        if r["buf"] is not None and r["buf"] >= a.buf_thresh:
            why.append(f"packet buffer {r['buf']}%")
        if r["desc"] is not None and r["desc"] >= a.desc_thresh:
            why.append(f"packet descriptor {r['desc']}%")
        if r["n99"] >= a.cores_thresh:
            why.append(f"{r['n99']} DP cores at 100%")
        if why:
            out.append((r["t"], "; ".join(why)))
    return out


class FreezeDetector:
    """New-connection rate collapsing while it was healthy a moment ago (the 10/21 11:22 signature: cps went to 0)."""

    def __init__(self, window=24, frac=0.1, min_cps=500):
        self.hist = collections.deque(maxlen=window)
        self.frac, self.min_cps = frac, min_cps

    def update(self, cps):
        if cps is None:
            return False
        base = statistics.median(self.hist) if len(self.hist) >= 6 else None
        hit = base is not None and base >= self.min_cps and cps <= base * self.frac
        if not hit:
            self.hist.append(cps)  # never let freeze samples drag the baseline down
        return hit


# ---------------------------------------------------------------------------------------------------------------------
# per-firewall worker
# ---------------------------------------------------------------------------------------------------------------------
class Worker:
    def __init__(self, fw, a, stop, log):
        self.fw, self.a, self.stop, self.log = fw, a, stop, log
        self.samples = collections.deque(maxlen=int(180 / max(a.interval, 1)) + 4)      # ~3 min of point samples
        self.backlogs = collections.deque(maxlen=int(120 / max(a.interval, 1)) + 2)     # ~2 min of raw backlog text
        self.seconds = collections.deque(maxlen=900)                                   # 15 min of per-second rows
        self.counters = collections.deque(maxlen=4)
        self.detector = FreezeDetector(frac=a.freeze_frac, min_cps=a.freeze_min_cps)
        self.last_t = 0
        self.last_raw = ""
        self.fmt = None
        self.parse_failures = 0
        self.ok_once = False      # has this firewall's API ever answered?
        self.pending = None       # open event: {"t0", "reasons", "deadline"}
        self.cool_until = 0.0
        self.suppressed = 0
        self.files = []
        self.n_samples = 0
        self.errors = collections.Counter()
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=3)

    # -- fetchers ---------------------------------------------------------------------------------------------------
    def fetch_seconds(self):
        t = now()
        try:
            root, raw, rtt = self.fw.op(SECOND_CMD, timeout=max(self.fw.timeout, 15))
        except Exception as e:
            self.errors["second"] += 1
            self.log(f"{self.fw.host}: second-fetch failed: {e}")
            return []
        self.ok_once = True
        self.last_raw = raw
        parsed = parse_second(root)
        self.fmt = parsed["fmt"]
        rows = per_second_rows(parsed, t)
        if not rows:
            self.parse_failures += 1
            self.log(f"{self.fw.host}: could not parse 'resource-monitor second' (raw kept in the next event file)")
            return []
        new = [r for r in rows if r["t"] > self.last_t]
        new.sort(key=lambda r: r["t"])
        if new:
            self.last_t = new[-1]["t"]
            self.seconds.extend(new)
            self.append_ndjson("seconds", new)
            for ts, why in detect_seconds(new, self.a):
                self.trigger(ts, why, "second")
        return new

    def fetch_counters(self):
        try:
            root, _, _ = self.fw.op(COUNTER_CMD, timeout=max(self.fw.timeout, 20))
        except Exception as e:
            self.errors["counters"] += 1
            self.log(f"{self.fw.host}: counter fetch failed: {e}")
            return {}
        snap = {"t": int(now()), "c": parse_counters(root)}
        self.counters.append(snap)
        self.append_ndjson("counters", [snap])
        return snap

    def point_sample(self):
        probes = {"clock": CLOCK_CMD, "session": SESSION_CMD, "backlog": BACKLOG_CMD}
        futs = {k: self.pool.submit(self._probe, c) for k, c in probes.items()}
        rec = {"t": round(now(), 1)}
        for k, f in futs.items():
            try:
                res = f.result(timeout=self.a.probe_timeout + 2)
            except Exception as e:  # a timeout during a freeze is itself evidence
                rec[k + "_err"] = type(e).__name__
                self.errors[k] += 1
                continue
            self.ok_once = True
            rec[k + "_ms"] = round(res["rtt"], 1)
            if k == "session":
                rec.update(res["data"])
            if k == "backlog":
                self.backlogs.append((rec["t"], res["raw"][:6000]))
        self.samples.append(rec)
        self.n_samples += 1
        self.append_ndjson("samples", [rec])
        if self.detector.update(rec.get("cps")):
            self.trigger(int(rec["t"]), f"new connections/s collapsed to {rec.get('cps')} (pps {rec.get('pps')})", "session")
        elif self.ok_once and len(self.samples) >= 2 and all(
                x.get("clock_err") or x.get("session_err") for x in list(self.samples)[-2:]):
            self.trigger(int(rec["t"]), f"API probes failing for 2 samples: {[k for k in rec if k.endswith('_err')]}", "probe")
        return rec

    def _probe(self, cmd):
        root, raw, rtt = self.fw.op(cmd, timeout=self.a.probe_timeout)
        return {"rtt": rtt, "raw": raw, "data": parse_session(root) if cmd == SESSION_CMD else {}}

    # -- events -----------------------------------------------------------------------------------------------------
    def trigger(self, ts, why, src):
        if now() < self.cool_until:
            self.suppressed += 1
            return
        if self.pending is None:
            self.pending = {"t0": ts, "reasons": [], "deadline": now() + self.a.post_secs}
            self.log(f"{self.fw.host}: EVENT at ~{stamp(ts)}: {why} ({src}); capturing {self.a.post_secs}s more")
        if len(self.pending["reasons"]) < 40:
            self.pending["reasons"].append({"t": ts, "why": why, "src": src})

    def maybe_flush(self, force=False):
        p = self.pending
        if p is None or (now() < p["deadline"] and not force):
            return
        self.fetch_seconds()            # one more per-second fetch so the file covers the whole event
        self.fetch_counters()
        t0 = p["t0"]
        lo, hi = t0 - self.a.pre_secs, t0 + self.a.post_secs
        bundle = {
            "host": self.fw.host, "trigger_time": stamp(t0), "trigger_epoch": t0, "reasons": p["reasons"],
            "params": {k: getattr(self.a, k) for k in ("interval", "buf_thresh", "desc_thresh", "cores_thresh", "freeze_frac")},
            "time_note": "per-second 't' is estimated from fetch time, good to about +-2 s",
            "seconds": [r for r in self.seconds if lo <= r["t"] <= hi],
            "samples": [s for s in self.samples if lo <= s["t"] <= hi + 30],
            "ingress_backlogs": [{"t": t, "raw": raw} for t, raw in self.backlogs if lo <= t <= hi + 30],
            "counters": list(self.counters)[-3:],
            "second_raw": self.last_raw[:200000], "second_format": self.fmt, "suppressed_triggers": self.suppressed,
        }
        name = f"event_{self.fw.host}_{dt.datetime.fromtimestamp(t0).strftime('%Y%m%d_%H%M%S')}.json.gz"
        path = os.path.join(self.a.out, name)
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            json.dump(bundle, fh)
        self.files.append(path)
        self.log(f"{self.fw.host}: wrote {name} ({len(bundle['seconds'])} seconds, {len(bundle['samples'])} samples)")
        self.pending = None
        self.cool_until = now() + self.a.cooldown
        self.suppressed = 0

    def append_ndjson(self, kind, items):
        if not self.a.keep_ndjson:
            return
        path = os.path.join(self.a.out, f"{kind}_{self.fw.host}_{dt.datetime.now().strftime('%Y%m%d%H')}.ndjson")
        with open(path, "a", encoding="utf-8") as fh:
            for it in items:
                fh.write(json.dumps(it) + "\n")

    # -- main loop --------------------------------------------------------------------------------------------------
    def run(self):
        a = self.a
        start = time.monotonic()
        self.fw.login()
        self.fetch_seconds()      # backfill: the previous 60 s, i.e. whatever happened before this job started
        self.fetch_counters()
        self.point_sample()
        if not self.ok_once:
            raise PanError(f"{self.fw.host}: no API response (check reachability, credentials, management ACL)")
        nxt, last_sec, last_cnt = time.monotonic(), time.monotonic(), time.monotonic()
        while not self.stop.is_set() and (a.duration <= 0 or time.monotonic() - start < a.duration):
            self.point_sample()
            m = time.monotonic()
            if m - last_sec >= a.second_interval:
                self.fetch_seconds()
                last_sec = time.monotonic()
            if m - last_cnt >= a.counter_interval:
                self.fetch_counters()
                last_cnt = time.monotonic()
            self.maybe_flush()
            nxt = max(nxt + a.interval, time.monotonic())
            self.stop.wait(max(0.0, nxt - time.monotonic()))
        self.fetch_seconds()      # cover the last seconds before exit
        self.maybe_flush(force=True)
        self.pool.shutdown(wait=False)


def once(fw, a):
    """One cycle with the parse printed, so a new firewall can be checked in seconds."""
    fw.login()
    w = Worker(fw, a, threading.Event(), print)
    a.keep_ndjson = False
    rows = w.fetch_seconds()
    print(f"{fw.host}: second data format={w.fmt}, seconds parsed={len(rows)}")
    if rows:
        print("  packet buffer max %s%%, descriptor max %s%%, max cores at 100%%: %s, newest second: %s" % (
            max((r['buf'] or 0) for r in rows), max((r['desc'] or 0) for r in rows), max(r['n99'] for r in rows), rows[-1]))
    s = w.point_sample()
    print(f"  point sample: {s}")
    c = w.fetch_counters()
    print(f"  counters matched: {len(c.get('c', {}))}")
    return bool(rows)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--fw", action="append", required=True, help="firewall management IP/host (repeat for each)")
    p.add_argument("--out", default="/tmp/pa_dp_poll")
    p.add_argument("--duration", type=float, default=0, help="seconds to run; 0 = until stopped")
    p.add_argument("--once", action="store_true", help="single cycle, print what was parsed, exit")
    p.add_argument("--interval", type=float, default=5, help="point-probe interval (s)")
    p.add_argument("--second-interval", type=float, default=45, help="'second last 60' fetch interval (s); must be < 60")
    p.add_argument("--counter-interval", type=float, default=60)
    p.add_argument("--probe-timeout", type=float, default=4)
    p.add_argument("--buf-thresh", type=int, default=20, help="packet buffer %% that counts as an event")
    p.add_argument("--desc-thresh", type=int, default=15)
    p.add_argument("--cores-thresh", type=int, default=8, help="DP cores at 100%% in one second that count as an event")
    p.add_argument("--freeze-frac", type=float, default=0.1)
    p.add_argument("--freeze-min-cps", type=int, default=500)
    p.add_argument("--pre-secs", type=int, default=90)
    p.add_argument("--post-secs", type=int, default=30)
    p.add_argument("--cooldown", type=int, default=120)
    p.add_argument("--keep-ndjson", action="store_true", help="also keep every sample/second row as ndjson (large)")
    p.add_argument("--verify-tls", action="store_true")
    p.add_argument("--scheme", default="https", help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    if a.second_interval >= 60:
        p.error("--second-interval must be below 60 or per-second history gets gaps")
    key, user, pw = (os.environ.get(k, "") for k in ("PANOS_API_KEY", "PANOS_USERNAME", "PANOS_PASSWORD"))
    if not key and not (user and pw):
        print("set PANOS_API_KEY or PANOS_USERNAME + PANOS_PASSWORD in the environment", file=sys.stderr)
        return 2
    os.makedirs(a.out, exist_ok=True)
    fws = [Fw(h, key, user, pw, a.verify_tls, scheme=a.scheme) for h in a.fw]
    if a.once:
        with concurrent.futures.ThreadPoolExecutor(len(fws)) as ex:
            ok = list(ex.map(lambda f: once(f, a), fws))
        return 0 if all(ok) else 1

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    lock = threading.Lock()

    def log(msg):
        with lock:
            print(f"{stamp()} {msg}", flush=True)

    workers = [Worker(f, a, stop, log) for f in fws]
    results = {}

    def go(w):
        try:
            w.run()
            results[w.fw.host] = "ok"
        except Exception as e:  # keep the other firewall running
            log(f"{w.fw.host}: poller stopped: {type(e).__name__}: {e}")
            results[w.fw.host] = f"failed: {type(e).__name__}: {e}"
            w.maybe_flush(force=True)

    threads = [threading.Thread(target=go, args=(w,), daemon=True) for w in workers]
    log(f"polling {', '.join(a.fw)} every {a.interval}s for {a.duration or 'ever'}s -> {a.out}")
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    summary = {"finished": stamp(), "result": results, "event_files": [f for w in workers for f in w.files],
               "samples": {w.fw.host: w.n_samples for w in workers}, "errors": {w.fw.host: dict(w.errors) for w in workers},
               "parse_failures": {w.fw.host: w.parse_failures for w in workers},
               "second_format": {w.fw.host: w.fmt for w in workers}}
    with open(os.path.join(a.out, "summary.json"), "w") as fh:
        json.dump(summary, fh, indent=1)
    log("summary: " + json.dumps(summary))
    return 0 if any(v == "ok" for v in results.values()) else 3


if __name__ == "__main__":
    sys.exit(main())
