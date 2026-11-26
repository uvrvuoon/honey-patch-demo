# -*- coding: utf-8 -*-
"""13주차 추가 검증 사례 — X-Forwarded-For 위조 / 같은 IP 동시 접속 / 공격 직후 정상 요청 (안지민).

    python tests/test_xff_cases.py                  # 기본 실행
    python tests/test_xff_cases.py --public-decoy   # data/decoy/public/report.txt 를 임시로 만들어
                                                    # sticky 가 응답 내용까지 바꾸는지 확인 (끝나면 삭제)

- 서버 ③만 대상 (X-Forwarded-For 는 서버 ③에서만 쓰임).
- 시나리오마다 서버 ③을 빈 포트로 새로 띄워 공격자 기억을 비운 상태에서 시작한다.
- 판정은 응답 내용(tests/test_cases.py 의 classify)과 logs/honeypatch.log 에 새로 생긴 줄(ip, event)로 한다.
- 실행 전 logs/honeypatch.log 를 백업하고 끝나면 되돌린다.
- 기대값(EXPECT)은 실행 전에 작성한 값이며, 실행 결과에 맞춰 고치지 않는다.
- 고정 사례 3종(tests/test_cases.py)은 건드리지 않는다.
"""
import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cases import DATA, DECOY_LOG, RESULT_DIR, classify, free_port, start_server  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
PUBLIC_DECOY = DATA / "decoy" / "public" / "report.txt"
ATTACK = "../secret/passwords.txt"
LOCAL = "127.0.0.1"
NO_HEADER = None

# ---------------------------------------------------------------------------
# 시나리오: 요청을 순서대로 보낸다.
#   (설명, file, X-Forwarded-For 값(None이면 헤더 없음), 기대 event, 기대 기록 IP)
#   기대 event: "attack" / "sticky" / None(기록 없음)
#   기대 응답 내용은 event 로 정해진다: attack -> 가짜, sticky -> 미끼 파일이 있으면 가짜·없으면 공개, None -> 공개
#   기대값은 "방어가 의도대로라면 이래야 한다"(README 6절 명세 + 정상 사용자 오탐 없음) 기준
# ---------------------------------------------------------------------------
SCENARIOS = [
    {"id": "X1", "group": "XFF 위조", "title": "공격 후 XFF 값을 바꿔 미끼에서 빠져나가는지",
     "steps": [
         ("공격자 공격", ATTACK, "10.0.0.66", "attack", "10.0.0.66"),
         ("같은 공격자가 XFF를 10.0.0.77로 바꿔 정상 요청", "report.txt", "10.0.0.77", "sticky", "10.0.0.66"),
     ]},
    {"id": "X2", "group": "XFF 위조", "title": "공격 후 XFF 헤더를 빼면 미끼에서 빠져나가는지",
     "steps": [
         ("공격자 공격", ATTACK, "10.0.0.66", "attack", "10.0.0.66"),
         ("같은 공격자가 헤더 없이 정상 요청", "report.txt", NO_HEADER, "sticky", "10.0.0.66"),
     ]},
    {"id": "X3", "group": "XFF 위조", "title": "공격자가 정상 사용자 IP로 위조해 공격하면 정상 사용자가 오탐되는지",
     "steps": [
         ("공격자가 XFF=10.0.0.10(정상 사용자 IP)으로 공격", ATTACK, "10.0.0.10", "attack", "10.0.0.10"),
         ("진짜 정상 사용자(10.0.0.10) 정상 요청", "report.txt", "10.0.0.10", None, None),
     ]},
    {"id": "X4", "group": "XFF 위조", "title": "XFF 첫 값이 비어 있으면(',') 접속 주소로 판단하는지",
     "steps": [
         ("XFF=',' 로 공격", ATTACK, ",", "attack", LOCAL),
     ]},
    {"id": "X5", "group": "XFF 위조", "title": "XFF 값 앞뒤 공백이 있어도 같은 공격자로 보는지",
     "steps": [
         ("공격자 공격", ATTACK, "10.0.0.66", "attack", "10.0.0.66"),
         ("같은 공격자가 XFF=' 10.0.0.66 ' 로 정상 요청", "report.txt", " 10.0.0.66 ", "sticky", "10.0.0.66"),
     ]},
    {"id": "S1", "group": "같은 IP", "title": "같은 IP(공유기 뒤 두 사람)에서 공격자 공격 후 정상 사용자가 오탐되는지",
     "steps": [
         ("공격자(10.0.0.50) 공격", ATTACK, "10.0.0.50", "attack", "10.0.0.50"),
         ("같은 IP의 다른 정상 사용자 정상 요청", "report.txt", "10.0.0.50", None, None),
     ]},
    {"id": "P1", "group": "공격 직후", "title": "공격 직후 같은 IP의 정상 요청 (명세: sticky)",
     "steps": [
         ("공격자 공격", ATTACK, "10.0.0.66", "attack", "10.0.0.66"),
         ("공격 직후 같은 IP 정상 요청", "report.txt", "10.0.0.66", "sticky", "10.0.0.66"),
     ]},
    {"id": "P2", "group": "공격 직후", "title": "공격 직후 같은 IP의 경계 사례 요청 (명세: sticky)",
     "steps": [
         ("공격자 공격", ATTACK, "10.0.0.66", "attack", "10.0.0.66"),
         ("공격 직후 같은 IP ..report.txt 요청", "..report.txt", "10.0.0.66", "sticky", "10.0.0.66"),
     ]},
    {"id": "P3", "group": "공격 직후", "title": "공격 직후 다른 IP의 정상 요청 (오탐 없음)",
     "steps": [
         ("공격자 공격", ATTACK, "10.0.0.66", "attack", "10.0.0.66"),
         ("공격 직후 다른 IP(10.0.0.10) 정상 요청", "report.txt", "10.0.0.10", None, None),
     ]},
]


# ---- 요청 / 로그 ------------------------------------------------------------
def read_log_lines():
    try:
        return DECOY_LOG.read_text("utf-8").splitlines()
    except OSError:
        return []


def send(port, name, xff):
    url = "http://127.0.0.1:%d/download?file=%s" % (port, urllib.parse.quote(name, safe=""))
    headers = {} if xff is None else {"X-Forwarded-For": xff}
    req = urllib.request.Request(url, headers=headers)
    try:
        with OPENER.open(req, timeout=10) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        status, raw = None, b""
    verdict, _, hits = classify(status, raw.decode("utf-8", "replace"))
    return status, verdict, hits


def has_decoy(name):
    return (DATA / "decoy" / "public" / name).is_file()


def expected_verdict(event, name):
    if event == "attack":
        return "fake"
    if event == "sticky" and has_decoy(name):
        return "fake"
    return "public"


def run_step(port, step):
    desc, name, xff, exp_event, exp_ip = step
    before = len(read_log_lines())
    status, verdict, hits = send(port, name, xff)
    time.sleep(0.05)
    new = [json.loads(l) for l in read_log_lines()[before:] if l.strip()]
    got_event = new[-1]["event"] if new else None
    got_ip = new[-1]["ip"] if new else None
    exp_verdict = expected_verdict(exp_event, name)
    diffs = []
    if got_event != exp_event:
        diffs.append("event 기대 %s / 실제 %s" % (exp_event, got_event))
    if exp_event is not None and got_ip != exp_ip:
        diffs.append("기록 IP 기대 %r / 실제 %r" % (exp_ip, got_ip))
    if verdict != exp_verdict:
        diffs.append("응답 기대 %s / 실제 %s" % (exp_verdict, verdict))
    if hits:
        diffs.append("진짜 비밀번호 %d개 노출" % hits)
    return {"desc": desc, "file": name, "xff": xff, "status": status, "verdict": verdict,
            "secret_hits": hits, "event": got_event, "ip": got_ip,
            "expect": {"event": exp_event, "ip": exp_ip, "verdict": exp_verdict},
            "pass": not diffs, "diffs": diffs}


# ---- 동시 접속 --------------------------------------------------------------
def concurrent(port, rounds, attacker_ip_fn, user_ip_fn):
    """라운드마다 공격 1건과 정상 요청 1건을 동시에 보낸다."""
    counts = {"user_sticky": 0, "user_fake": 0, "attack_not_fake": 0, "secret_hits": 0}
    for i in range(rounds):
        out = {}
        gate = threading.Barrier(2)

        def attack(ip=attacker_ip_fn(i)):
            gate.wait()
            out["a"] = send(port, ATTACK, ip)

        def normal(ip=user_ip_fn(i)):
            gate.wait()
            out["n"] = send(port, "report.txt", ip)

        before = len(read_log_lines())
        ts = [threading.Thread(target=attack), threading.Thread(target=normal)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        time.sleep(0.02)
        new = [json.loads(l) for l in read_log_lines()[before:] if l.strip()]
        if any(e["event"] == "sticky" and e["path"] == "report.txt" for e in new):
            counts["user_sticky"] += 1
        if out["n"][1] == "fake":
            counts["user_fake"] += 1
        if out["a"][1] != "fake":
            counts["attack_not_fake"] += 1
        counts["secret_hits"] += out["a"][2] + out["n"][2]
    return counts


# ---- 실행 ------------------------------------------------------------------
def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    p = argparse.ArgumentParser(description="XFF 위조·같은 IP 동시 접속·공격 직후 정상 요청 시험 (서버 ③)")
    p.add_argument("--public-decoy", action="store_true",
                   help="data/decoy/public/report.txt 를 임시로 만들어 sticky 의 응답 내용 영향 확인")
    p.add_argument("--rounds", type=int, default=30, help="동시 접속 시험 라운드 수 (기본 30)")
    p.add_argument("--no-save", action="store_true")
    a = p.parse_args()

    log_backup = DECOY_LOG.read_bytes() if DECOY_LOG.exists() else None
    made_decoy = False
    if a.public_decoy and not PUBLIC_DECOY.exists():
        PUBLIC_DECOY.parent.mkdir(parents=True, exist_ok=True)
        PUBLIC_DECOY.write_text("[공개 문서] 가짜 보고서 (sticky 확인용 임시 미끼)\n", encoding="utf-8")
        made_decoy = True

    results, conc = [], {}
    try:
        for sc in SCENARIOS:
            port = free_port()
            proc = start_server("honeypatch_server.py", port)
            try:
                steps = [run_step(port, st) for st in sc["steps"]]
            finally:
                proc.kill()
                proc.wait()
            ok = all(s["pass"] for s in steps)
            results.append({"id": sc["id"], "group": sc["group"], "title": sc["title"],
                            "steps": steps, "pass": ok})
            print("[%s] %s — %s" % (sc["id"], sc["title"], "기대대로" if ok else "기대와 다름"))
            for s in steps:
                print("     %-4s %s | file=%r XFF=%r -> %s %s, event=%s, ip=%r"
                      % ("OK" if s["pass"] else "DIFF", s["desc"], s["file"], s["xff"],
                         s["status"], s["verdict"], s["event"], s["ip"]))
                for d in s["diffs"]:
                    print("          ↑ %s" % d)
            print()

        for key, title, afn, ufn in (
                ("S2", "같은 IP에서 공격·정상 요청 동시 전송", lambda i: "10.1.0.%d" % i, lambda i: "10.1.0.%d" % i),
                ("S3", "다른 IP에서 공격·정상 요청 동시 전송", lambda i: "10.2.0.%d" % i, lambda i: "10.3.0.%d" % i)):
            port = free_port()
            proc = start_server("honeypatch_server.py", port)
            try:
                c = concurrent(port, a.rounds, afn, ufn)
            finally:
                proc.kill()
                proc.wait()
            conc[key] = dict(c, title=title, rounds=a.rounds)
            print("[%s] %s (%d라운드): 정상 요청 sticky 기록 %d회, 정상 요청이 가짜 응답 %d회, "
                  "공격이 가짜가 아닌 응답 %d회, 진짜 비밀번호 노출 %d"
                  % (key, title, a.rounds, c["user_sticky"], c["user_fake"],
                     c["attack_not_fake"], c["secret_hits"]))
    finally:
        if made_decoy:
            PUBLIC_DECOY.unlink()
            try:
                PUBLIC_DECOY.parent.rmdir()
            except OSError:
                pass
        if log_backup is None:
            if DECOY_LOG.exists():
                DECOY_LOG.unlink()
        else:
            DECOY_LOG.write_bytes(log_backup)

    if not a.no_save:
        save(results, conc, a)


def save(results, conc, a):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    name = "xff_results_public_decoy" if a.public_decoy else "xff_results"
    cmd = "python tests/test_xff_cases.py" + (" --public-decoy" if a.public_decoy else "")
    md = ["# 추가 검증 사례 — XFF 위조 / 같은 IP 동시 접속 / 공격 직후 정상 요청 (서버 ③)", "",
          "- 실행 시각: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
          "- 실행 명령: `%s`" % cmd,
          "- Python: %s / OS: %s" % (sys.version.split()[0], sys.platform),
          "- 임시 미끼 data/decoy/public/report.txt: %s" % ("있음" if a.public_decoy else "없음"), "",
          "| 번호 | 단계 | file | XFF | 기대 (event / 기록 IP / 응답) | 실제 (event / 기록 IP / 응답) | 결과 |",
          "|---|---|---|---|---|---|---|"]
    for r in results:
        for i, s in enumerate(r["steps"], 1):
            e = s["expect"]
            md.append("| %s-%d | %s | `%s` | %s | %s / %s / %s | %s / %s / %s | %s |" % (
                r["id"], i, s["desc"], s["file"],
                "(없음)" if s["xff"] is None else "`%r`" % s["xff"],
                e["event"] or "-", e["ip"] or "-", e["verdict"],
                s["event"] or "-", "-" if s["ip"] is None else repr(s["ip"]), s["verdict"],
                "일치" if s["pass"] else "**불일치**"))
    md += ["", "| 번호 | 동시 접속 시험 | 라운드 | 정상 요청 sticky 기록 | 정상 요청이 가짜 응답 | 공격이 가짜가 아닌 응답 | 진짜 비밀 노출 |",
           "|---|---|---|---|---|---|---|"]
    for k, c in conc.items():
        md.append("| %s | %s | %d | %d | %d | %d | %d |" % (
            k, c["title"], c["rounds"], c["user_sticky"], c["user_fake"],
            c["attack_not_fake"], c["secret_hits"]))
    (RESULT_DIR / (name + ".md")).write_text("\n".join(md) + "\n", encoding="utf-8")
    (RESULT_DIR / (name + ".json")).write_text(json.dumps(
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "command": cmd,
         "scenarios": results, "concurrent": conc}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print("\n결과 저장: tests/results/%s.md, .json" % name)


if __name__ == "__main__":
    main()
