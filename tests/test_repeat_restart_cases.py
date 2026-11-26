# -*- coding: utf-8 -*-
"""13주차 추가 검증 사례 — 같은 공격 반복 / 미끼 없는 파일 공격 / 서버 ③ 재시작 후 상태 (이수빈).

    python tests/test_repeat_restart_cases.py            # 기본 실행 (반복 20회, 동시 30건)
    python tests/test_repeat_restart_cases.py --repeat 50 --burst 50

- 시나리오마다 서버(①②③)를 빈 포트로 새로 띄워 공격자 기억이 빈 상태에서 시작한다.
- 판정은 응답 내용(tests/test_cases.py 의 classify)과 logs/honeypatch.log 에 새로 생긴 줄로 한다.
- 실행 전 logs/honeypatch.log 를 백업하고 끝나면 되돌린다.
- 기대값(각 시나리오의 expect)은 실행 전에 README 6·8절 명세 기준으로 작성했고,
  실행 결과에 맞춰 고치지 않는다. 명세와 허니패치 목표(공격이 성공한 것처럼 보임)가
  서로 다른 곳은 'note'에 따로 적었다.
- 고정 사례 3종(tests/test_cases.py)과 지민 사례(tests/test_xff_cases.py)는 건드리지 않는다.
"""
import argparse
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cases import DATA, DECOY_LOG, RESULT_DIR, ROOT, classify, free_port, start_server  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ATTACK = "../secret/passwords.txt"
ATTACKER = "10.0.0.66"
USER = "10.0.0.10"
SCRIPTS = {1: "vulnerable_server.py", 2: "patched_server.py", 3: "honeypatch_server.py"}
MARK = {1: "①", 2: "②", 3: "③"}

# data/public 에서 파일 시스템 맨 위까지 올라가는 '../' 개수 (+여유 2)
_UP = "../" * (len(Path(os.path.realpath(DATA / "public")).parts) + 2)
if os.name == "nt":
    OS_FILE_NAME, OS_FILE = "C:\\Windows\\win.ini", _UP + "Windows/win.ini"
else:
    OS_FILE_NAME, OS_FILE = "/etc/passwd", _UP + "etc/passwd"

COMMON_PY = "../../servers/common.py"


# ---- 요청 / 로그 ------------------------------------------------------------
def read_log():
    try:
        return [json.loads(l) for l in DECOY_LOG.read_text("utf-8").splitlines() if l.strip()]
    except OSError:
        return []


def log_line_count():
    try:
        return len(DECOY_LOG.read_text("utf-8").splitlines())
    except OSError:
        return 0


def send(port, name, xff):
    url = "http://127.0.0.1:%d/download?file=%s" % (port, urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={"X-Forwarded-For": xff})
    try:
        with OPENER.open(req, timeout=10) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        status, raw = None, b""
    body = raw.decode("utf-8", "replace")
    verdict, _, hits = classify(status, body)
    return {"status": status, "verdict": verdict, "secret_hits": hits, "body": body}


def file_text(rel_from_public):
    """data/public 기준 상대 경로의 실제 파일 내용 (없으면 None).
    서버는 파일을 바이트 그대로 보내므로 줄바꿈 변환 없이 읽는다
    (read_text는 줄바꿈 CRLF를 LF로 바꿔서 win.ini 같은 CRLF 파일과 비교가 어긋남)."""
    try:
        raw = Path(os.path.realpath(DATA / "public" / rel_from_public)).read_bytes()
        return raw.decode("utf-8", "replace")
    except OSError:
        return None


class Servers:
    """필요한 서버만 빈 포트로 띄우고, ③은 재시작할 수 있게 관리"""

    def __init__(self, ids):
        self.port, self.proc = {}, {}
        for i in ids:
            self.start(i)

    def start(self, i):
        self.port[i] = free_port()
        self.proc[i] = start_server(SCRIPTS[i], self.port[i])

    def stop(self, i):
        self.proc[i].terminate()
        self.proc[i].wait()

    def restart(self, i):
        self.stop(i)
        self.start(i)

    def close(self):
        for p in self.proc.values():
            if p.poll() is None:
                p.terminate()
                p.wait()


# ---- 판정 보조 --------------------------------------------------------------
def compare(expect, got):
    diffs = []
    for k, want in expect.items():
        have = got.get(k)
        if want != have:
            diffs.append("%s 기대 %r / 실제 %r" % (k, want, have))
    return diffs


def step_result(desc, server, name, xff, expect, got, note=""):
    diffs = compare(expect, got)
    return {"desc": desc, "server": MARK[server], "file": name, "xff": xff,
            "expect": expect, "got": got, "pass": not diffs, "diffs": diffs, "note": note}


def one(sv, server, name, xff):
    """요청 1건 + 그 요청으로 새로 생긴 ③ 로그 (event, ip)"""
    before = log_line_count()
    r = send(sv.port[server], name, xff)
    time.sleep(0.05)
    new = read_log()[before:] if server == 3 else []
    r["event"] = new[-1]["event"] if new else None
    r["log_ip"] = new[-1]["ip"] if new else None
    r["new_log_lines"] = len(new)
    return r


# ---- 시나리오 ---------------------------------------------------------------
def scenario_R1(n):
    """같은 공격을 n번 순서대로 반복 — 응답이 매번 같은지, 로그가 n줄 쌓이는지"""
    sv = Servers([1, 2, 3])
    steps = []
    try:
        for s, exp in ((1, {"status": 200, "verdict": "leak", "secret_hits": 3}),
                       (2, {"status": 403, "verdict": "blocked", "secret_hits": 0}),
                       (3, {"status": 200, "verdict": "fake", "secret_hits": 0})):
            before = log_line_count()
            outs = [send(sv.port[s], ATTACK, ATTACKER) for _ in range(n)]
            time.sleep(0.05)
            new = read_log()[before:]
            got = {
                "status": outs[0]["status"] if len({o["status"] for o in outs}) == 1 else "섞임",
                "verdict": outs[0]["verdict"] if len({o["verdict"] for o in outs}) == 1 else "섞임",
                "secret_hits": max(o["secret_hits"] for o in outs) if s == 1 else sum(o["secret_hits"] for o in outs),
                "body_kinds": len({o["body"] for o in outs}),
            }
            exp = dict(exp, body_kinds=1)
            if s == 3:
                got["attack_lines"] = sum(1 for e in new if e["event"] == "attack" and e["ip"] == ATTACKER)
                got["other_lines"] = len(new) - got["attack_lines"]
                exp.update(attack_lines=n, other_lines=0)
            steps.append(step_result("같은 공격 %d회 순서대로" % n, s, ATTACK, ATTACKER, exp, got))
    finally:
        sv.close()
    return steps


def scenario_R2(n):
    """같은 공격 n건을 동시에 — 응답이 모두 가짜인지, 로그 줄이 깨지지 않고 n줄인지"""
    sv = Servers([3])
    try:
        before_lines = log_line_count()
        gate = threading.Barrier(n)
        outs = [None] * n

        def worker(i):
            gate.wait()
            outs[i] = send(sv.port[3], ATTACK, ATTACKER)

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        time.sleep(0.1)
        raw_new = DECOY_LOG.read_text("utf-8").splitlines()[before_lines:]
        broken = 0
        for l in raw_new:
            try:
                json.loads(l)
            except ValueError:
                broken += 1
        got = {"fake": sum(1 for o in outs if o and o["verdict"] == "fake"),
               "secret_hits": sum(o["secret_hits"] for o in outs if o),
               "log_lines": len(raw_new), "broken_lines": broken}
        exp = {"fake": n, "secret_hits": 0, "log_lines": n, "broken_lines": 0}
    finally:
        sv.close()
    return [step_result("같은 공격 %d건 동시 전송" % n, 3, ATTACK, ATTACKER, exp, got)]


def scenario_R3(n):
    """공격 1번 뒤 같은 IP가 정상 파일을 n번 — 매번 sticky로 기록되는지"""
    sv = Servers([3])
    steps = []
    try:
        r = one(sv, 3, ATTACK, ATTACKER)
        steps.append(step_result("공격 1회", 3, ATTACK, ATTACKER,
                                 {"verdict": "fake", "event": "attack"},
                                 {"verdict": r["verdict"], "event": r["event"]}))
        before = log_line_count()
        outs = [send(sv.port[3], "report.txt", ATTACKER) for _ in range(n)]
        time.sleep(0.05)
        new = read_log()[before:]
        got = {"verdict": outs[0]["verdict"] if len({o["verdict"] for o in outs}) == 1 else "섞임",
               "sticky_lines": sum(1 for e in new if e["event"] == "sticky"),
               "secret_hits": sum(o["secret_hits"] for o in outs)}
        steps.append(step_result("같은 IP가 report.txt %d회" % n, 3, "report.txt", ATTACKER,
                                 {"verdict": "public", "sticky_lines": n, "secret_hits": 0}, got))
    finally:
        sv.close()
    return steps


def scenario_M(case_id, name, label, exist_text):
    """미끼가 없는 파일을 공격 — ① 유출, ② 403, ③ 404(README 6절: 가짜 파일이 없으면 404)"""
    sv = Servers([1, 2, 3])
    steps = []
    try:
        exists = exist_text is not None
        # ①: 파일이 실제로 있으면 그 내용 그대로 유출(200), 없으면 404
        r1 = one(sv, 1, name, ATTACKER)
        got1 = {"status": r1["status"], "same_as_real_file": exists and r1["body"] == exist_text}
        exp1 = {"status": 200 if exists else 404, "same_as_real_file": exists}
        steps.append(step_result(label, 1, name, ATTACKER, exp1, got1))

        r2 = one(sv, 2, name, ATTACKER)
        steps.append(step_result(label, 2, name, ATTACKER, {"status": 403}, {"status": r2["status"]}))

        r3 = one(sv, 3, name, ATTACKER)
        leaked = exists and exist_text.strip() != "" and exist_text.strip() in r3["body"]
        got3 = {"status": r3["status"], "event": r3["event"], "log_ip": r3["log_ip"],
                "real_content_leaked": leaked, "secret_hits": r3["secret_hits"]}
        exp3 = {"status": 404, "event": "attack", "log_ip": ATTACKER,
                "real_content_leaked": False, "secret_hits": 0}
        note = ""
        if exists:
            note = ("명세상 404가 맞지만, 무방비 서버(①)라면 200이 나왔을 파일이라 "
                    "공격자가 ③을 '무방비 서버가 아님'으로 구분할 수 있음")
        steps.append(step_result(label, 3, name, ATTACKER, exp3, got3, note))

        # 미끼 없는 파일 공격 뒤에도 공격자로 기억되는지
        r4 = one(sv, 3, "report.txt", ATTACKER)
        steps.append(step_result("위 공격 직후 같은 IP가 report.txt", 3, "report.txt", ATTACKER,
                                 {"verdict": "public", "event": "sticky"},
                                 {"verdict": r4["verdict"], "event": r4["event"]}))
    finally:
        sv.close()
    return steps


def scenario_RS():
    """서버 ③ 재시작 전·후 — 공격자 기억은 사라지고(README 8절), 로그 파일은 남는지"""
    sv = Servers([3])
    steps = []
    try:
        r = one(sv, 3, ATTACK, ATTACKER)
        steps.append(step_result("재시작 전: 공격", 3, ATTACK, ATTACKER,
                                 {"verdict": "fake", "event": "attack"},
                                 {"verdict": r["verdict"], "event": r["event"]}))
        r = one(sv, 3, "report.txt", ATTACKER)
        steps.append(step_result("재시작 전: 같은 IP report.txt", 3, "report.txt", ATTACKER,
                                 {"verdict": "public", "event": "sticky"},
                                 {"verdict": r["verdict"], "event": r["event"]}))

        lines_before = log_line_count()
        sv.restart(3)
        lines_after = log_line_count()
        steps.append(step_result("재시작 직후: 로그 파일", 3, "-", "-",
                                 {"log_lines_kept": True},
                                 {"log_lines_kept": lines_after == lines_before and lines_before > 0}))

        r = one(sv, 3, "report.txt", ATTACKER)
        steps.append(step_result("재시작 후: 같은 IP report.txt", 3, "report.txt", ATTACKER,
                                 {"verdict": "public", "event": None},
                                 {"verdict": r["verdict"], "event": r["event"]},
                                 "공격자 기억이 메모리에만 있어 재시작하면 sticky가 풀림 (README 8절)"))
        r = one(sv, 3, ATTACK, ATTACKER)
        steps.append(step_result("재시작 후: 같은 IP 다시 공격", 3, ATTACK, ATTACKER,
                                 {"verdict": "fake", "event": "attack", "secret_hits": 0},
                                 {"verdict": r["verdict"], "event": r["event"],
                                  "secret_hits": r["secret_hits"]}))
        r = one(sv, 3, "report.txt", ATTACKER)
        steps.append(step_result("재시작 후 재공격 뒤: 같은 IP report.txt", 3, "report.txt", ATTACKER,
                                 {"verdict": "public", "event": "sticky"},
                                 {"verdict": r["verdict"], "event": r["event"]}))
    finally:
        sv.close()
    return steps


# ---- 실행 ------------------------------------------------------------------
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    p = argparse.ArgumentParser(description="같은 공격 반복·미끼 없는 파일·서버 ③ 재시작 시험")
    p.add_argument("--repeat", type=int, default=20, help="순서대로 반복 횟수 (기본 20)")
    p.add_argument("--burst", type=int, default=30, help="동시 전송 건수 (기본 30)")
    p.add_argument("--no-save", action="store_true")
    a = p.parse_args()

    DECOY_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_backup = DECOY_LOG.read_bytes() if DECOY_LOG.exists() else None

    plan = [
        ("R1", "반복", "같은 공격을 순서대로 반복해도 응답이 매번 같고 로그가 반복 수만큼 쌓이는지",
         lambda: scenario_R1(a.repeat)),
        ("R2", "반복", "같은 공격을 동시에 보내도 모두 가짜이고 로그 줄이 깨지지 않는지",
         lambda: scenario_R2(a.burst)),
        ("R3", "반복", "공격 뒤 같은 IP의 정상 요청을 반복해도 매번 sticky인지",
         lambda: scenario_R3(a.repeat)),
        ("M1", "미끼 없음", "실제로 있는 data 밖 파일(servers/common.py) 공격",
         lambda: scenario_M("M1", COMMON_PY, "소스 코드 파일 공격", file_text(COMMON_PY))),
        ("M2", "미끼 없음", "운영체제 기본 파일(%s) 공격" % OS_FILE_NAME,
         lambda: scenario_M("M2", OS_FILE, "OS 파일 공격", file_text(OS_FILE))),
        ("M3", "미끼 없음", "어디에도 없는 파일(../secret/none.txt) 공격",
         lambda: scenario_M("M3", "../secret/none.txt", "없는 파일 공격", None)),
        ("RS", "재시작", "서버 ③ 재시작 전·후 공격자 기억과 로그 파일 상태",
         scenario_RS),
    ]

    results = []
    try:
        for sid, group, title, fn in plan:
            steps = fn()
            ok = all(s["pass"] for s in steps)
            results.append({"id": sid, "group": group, "title": title, "steps": steps, "pass": ok})
            print("[%s] %s — %s" % (sid, title, "기대대로" if ok else "기대와 다름"))
            for s in steps:
                print("     %-4s %s %s | file=%r -> %s" % ("OK" if s["pass"] else "DIFF", s["server"],
                                                       s["desc"], s["file"], json.dumps(s["got"], ensure_ascii=False)))
                for d in s["diffs"]:
                    print("          ↑ %s" % d)
                if s["note"]:
                    print("          * %s" % s["note"])
            print()
    finally:
        if log_backup is None:
            if DECOY_LOG.exists():
                DECOY_LOG.unlink()
        else:
            DECOY_LOG.write_bytes(log_backup)

    secret_total = sum(s["got"].get("secret_hits", 0) for r in results for s in r["steps"]
                       if s["server"] == "③")
    print("서버 ③ 응답 속 진짜 비밀번호: 총 %d개" % secret_total)
    print("결과: %d/%d 시나리오 기대대로" % (sum(r["pass"] for r in results), len(results)))
    if not a.no_save:
        save(results, a, secret_total)
    return 0 if all(r["pass"] for r in results) else 1


def _fmt(d):
    return ", ".join("%s=%s" % (k, "-" if v is None else v) for k, v in d.items())


def save(results, a, secret_total):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = "python tests/test_repeat_restart_cases.py --repeat %d --burst %d" % (a.repeat, a.burst)
    md = ["# 추가 검증 사례 — 같은 공격 반복 / 미끼 없는 파일 공격 / 서버 ③ 재시작 (이수빈)", "",
          "- 실행 시각: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
          "- 실행 명령: `%s`" % cmd,
          "- Python: %s / OS: %s" % (sys.version.split()[0], sys.platform),
          "- 기대값은 실행 전에 작성 (README 6·8절 명세 기준), 결과에 맞춰 고치지 않음",
          "- 서버 ③ 응답 속 진짜 비밀번호: **총 %d개**" % secret_total, "",
          "| 번호 | 서버 | 단계 | file | 기대 | 실제 | 결과 |",
          "|---|---|---|---|---|---|---|"]
    for r in results:
        for i, s in enumerate(r["steps"], 1):
            md.append("| %s-%d | %s | %s | `%s` | %s | %s | %s |" % (
                r["id"], i, s["server"], s["desc"], s["file"], _fmt(s["expect"]), _fmt(s["got"]),
                "일치" if s["pass"] else "**불일치**"))
    notes = [(r["id"], i, s["note"]) for r in results for i, s in enumerate(r["steps"], 1) if s["note"]]
    if notes:
        md += ["", "## 참고 (명세와 허니패치 목표의 차이)", ""]
        md += ["- %s-%d: %s" % n for n in notes]
    (RESULT_DIR / "repeat_restart_results.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (RESULT_DIR / "repeat_restart_results.json").write_text(json.dumps(
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "command": cmd,
         "python": sys.version.split()[0], "os": sys.platform,
         "scenarios": results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("결과 저장: tests/results/repeat_restart_results.md, .json")


if __name__ == "__main__":
    sys.exit(main())
