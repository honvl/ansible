"""Tests for scripts/pa_dp_poller.py (standard library only):  python3 -m unittest discover -s tests -v"""
import gzip
import http.server
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import pa_dp_poller as pp  # noqa: E402

FIXTURE = os.path.join(HERE, "fixtures", "resource_monitor_second.txt")  # real 'second' output taken from a PA-3420 tech support file


def fixture():
    with open(FIXTURE) as fh:
        return fh.read()


def xml_second(buf, cores=None):
    """Structured form (field names as documented for the XML API; the text form above is the verified one)."""
    cores = cores or {1: [60] * len(buf), 2: [61] * len(buf)}
    ent = "".join(f"<entry><coreid>{c}</coreid><value>{','.join(map(str, v))}</value></entry>" for c, v in cores.items())
    return ET.fromstring(
        "<response status='success'><result><resource-monitor><data-processors><dp0><second>"
        f"<cpu-load-maximum>{ent}</cpu-load-maximum><resource-utilization>"
        f"<entry><name>packet buffer</name><value>{','.join(map(str, buf))}</value></entry>"
        f"<entry><name>packet descriptor</name><value>{','.join(['2'] * len(buf))}</value></entry>"
        "</resource-utilization></second></dp0></data-processors></resource-monitor></result></response>")


class Args:
    interval, buf_thresh, desc_thresh, cores_thresh = 0.2, 20, 15, 8
    freeze_frac, freeze_min_cps, probe_timeout = 0.1, 500, 2
    pre_secs, post_secs, cooldown, second_interval, counter_interval = 30, 1, 60, 45, 60
    keep_ndjson, out, duration = False, "", 0


class ParseTests(unittest.TestCase):
    def test_real_text_sample(self):
        r = pp.parse_second_text(fixture())
        self.assertEqual(sorted(r["cores"]), list(range(1, 14)))            # '*' columns are not dataplane cores
        self.assertTrue(all(len(v) == 60 for v in r["cores"].values()))
        self.assertEqual({k: len(v) for k, v in r["util"].items()},
                         {"session": 60, "packet buffer": 60, "packet descriptor": 60, "sw tags descriptor": 60})
        self.assertEqual(r["cores"][1][0], 67)                               # newest row first
        rows = pp.per_second_rows(r, 1_000_000)
        self.assertEqual(len(rows), 60)
        self.assertEqual(rows[0]["t"], 999_999)
        self.assertEqual(rows[59]["t"], 999_940)
        self.assertEqual(max(x["n99"] for x in rows), 0)

    def test_xml_second_and_cdata_fallback(self):
        r = pp.parse_second(xml_second([1, 2, 96, 3]))
        self.assertEqual(r["fmt"], "xml")
        self.assertEqual(r["util"]["packet buffer"], [1, 2, 96, 3])
        text = fixture()
        empty = pp.parse_second(ET.fromstring("<response status='success'><result></result></response>"))
        self.assertEqual(empty["cores"], {})                                 # nothing parseable -> caller treats as parse failure
        root = ET.Element("response", status="success")
        ET.SubElement(root, "result").text = text
        self.assertEqual(pp.parse_second(root)["fmt"], "text")

    def test_session_and_counters(self):
        root = ET.fromstring("<response status='success'><result><num-active>41000</num-active><pps>55000</pps>"
                             "<cps>0</cps><kbps>400000</kbps></result></response>")
        self.assertEqual(pp.parse_session(root), {"num_active": 41000, "pps": 55000, "cps": 0, "kbps": 400000})
        c = ET.fromstring("<response status='success'><result><global><counters>"
                          "<entry><name>log_traffic_loss_queue_full</name><value>9</value></entry>"
                          "<entry><name>some_other_counter</name><value>5</value></entry>"
                          "<entry><name>pkt_sent_host_drop</name><value>7</value></entry>"
                          "</counters></global></result></response>")
        self.assertEqual(pp.parse_counters(c), {"log_traffic_loss_queue_full": 9, "pkt_sent_host_drop": 7})


class DetectTests(unittest.TestCase):
    def test_buffer_spike_is_found_at_its_second(self):
        buf = [1] * 60
        buf[20] = 96                                                         # 20 s before the newest second
        rows = pp.per_second_rows(pp.parse_second(xml_second(buf, {1: [100] * 60, 2: [50] * 60})), 5000)
        ev = pp.detect_seconds(rows, Args)
        self.assertEqual([t for t, _ in ev][:1], [5000 - 1 - 20])
        self.assertIn("packet buffer 96%", ev[0][1])

    def test_quiet_data_gives_no_events(self):
        rows = pp.per_second_rows(pp.parse_second_text(fixture()), 5000)
        self.assertEqual(pp.detect_seconds(rows, Args), [])

    def test_freeze_detector(self):
        d = pp.FreezeDetector()
        self.assertFalse(any(d.update(5000 + i) for i in range(24)))
        self.assertTrue(d.update(0))
        self.assertTrue(d.update(0))                                         # baseline not poisoned by freeze samples
        self.assertFalse(d.update(5200))
        self.assertFalse(pp.FreezeDetector().update(0))                      # no baseline yet -> no alarm
        low = pp.FreezeDetector()
        [low.update(20) for _ in range(10)]
        self.assertFalse(low.update(0))                                      # an idle unit is not a freeze


class FakeFw:
    """Stands in for the XML API; serves a healthy firewall, then cps=0 plus a buffer spike."""
    host = "10.0.0.1"
    timeout = 2

    def __init__(self):
        self.t0, self.n = time.time(), 0

    def login(self):
        pass

    def op(self, cmd, timeout=None):
        frozen = time.time() - self.t0 > 0.6
        if cmd == pp.SESSION_CMD:
            cps = 0 if frozen else 5000
            return ET.fromstring(f"<response status='success'><result><cps>{cps}</cps><pps>55000</pps></result></response>"), "<raw/>", 3.0
        if cmd == pp.SECOND_CMD:
            buf = [96 if (frozen and i in (3, 4)) else 1 for i in range(60)]
            return xml_second(buf), "<raw-second/>", 20.0
        if cmd == pp.COUNTER_CMD:
            return ET.fromstring("<response status='success'><result><global><counters><entry><name>pkt_sent_host_drop</name>"
                                 f"<value>{100 + self.n}</value></entry></counters></global></result></response>"), "", 50.0
        return ET.fromstring("<response status='success'><result>ok</result></response>"), "backlog-text", 2.0


class LoopTests(unittest.TestCase):
    def test_event_bundle_is_written(self):
        with tempfile.TemporaryDirectory() as d:
            a = Args()
            a.out, a.duration, a.second_interval, a.counter_interval = d, 2.5, 0.5, 0.5
            logs = []
            w = pp.Worker(FakeFw(), a, threading.Event(), logs.append)
            w.run()
            files = [f for f in os.listdir(d) if f.startswith("event_")]
            self.assertEqual(len(files), 1, logs)                            # cooldown keeps one sustained event to one file
            bundle = json.load(gzip.open(os.path.join(d, files[0]), "rt"))
            self.assertTrue(bundle["reasons"])
            self.assertTrue(bundle["seconds"])
            self.assertTrue(bundle["samples"])
            self.assertIn("pkt_sent_host_drop", json.dumps(bundle["counters"]))
            self.assertEqual(bundle["second_raw"], "<raw-second/>")


class DeadFw(FakeFw):
    def op(self, cmd, timeout=None):
        raise OSError("connection refused")


class UnreachableTests(unittest.TestCase):
    def test_never_answering_firewall_fails_instead_of_reporting_ok(self):
        with tempfile.TemporaryDirectory() as d:
            a = Args()
            a.out, a.duration = d, 5
            w = pp.Worker(DeadFw(), a, threading.Event(), lambda *_: None)
            with self.assertRaises(pp.PanError):
                w.run()
            self.assertEqual([f for f in os.listdir(d) if f.startswith("event_")], [])   # no event spam for a config error


class Handler(http.server.BaseHTTPRequestHandler):
    seen = {}

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        Handler.seen = {"key": self.headers.get("X-PAN-KEY"), "body": body, "path": self.path}
        data = b"<response status='success'><result><cps>12</cps></result></response>"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


class ClientTests(unittest.TestCase):
    def test_key_goes_in_header_not_url(self):
        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            fw = pp.Fw(f"127.0.0.1:{srv.server_port}", key="SECRETKEY", scheme="http")
            root, raw, rtt = fw.op(pp.SESSION_CMD)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(Handler.seen["key"], "SECRETKEY")
        self.assertNotIn("SECRETKEY", Handler.seen["path"] + Handler.seen["body"])
        self.assertEqual(pp.parse_session(root), {"cps": 12})


if __name__ == "__main__":
    unittest.main()
