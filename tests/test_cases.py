# -*- coding: utf-8 -*-
"""고정 검증 사례 3종 자동 실행 · 서버 ①②③ 비교 (김진하).

    python tests/test_cases.py                 # 서버 ①②③을 빈 포트로 직접 띄워 실행
    python tests/test_cases.py --use-running   # 이미 켜 둔 8001/8002/8003 에 그대로 요청
    python tests/test_cases.py --repeat 100    # 위반 사례 응답 시간 비교(① vs ③) 추가 실행

하는 일
  1. 11주차에 고정한 검증 사례 3종(정상/위반/경계)을 서버 ①②③에 같은 입력으로 보낸다.
  2. 응답을 data/public·data/secret·data/decoy 의 실제 파일 내용과 대조해
     '공개 파일 / 진짜 비밀 유출 / 가짜 파일(미끼)' 을 판정한다.
  3. 서버 ③은 logs/honeypatch.log 가 요청 중에 늘었는지로 미끼 전환 여부를 본다.
  4. 11주차 기대 결과표(README 3-2)와 대조해 PASS/FAIL 을 낸다.

고정 규칙: EXPECTED(기대값)는 실행 결과에 맞춰 고치지 않는다.
          결과가 다르면 기대값이 아니라 구현을 고치거나 원인을 기록한다.

판정은 공격자가 받는 응답만 보는 것이 아니라 방어자 쪽 정보(실제 파일 내용, 서버 ③ 로그)로 한다.
표준 라이브러리만 사용한다(저장소 전체 방침과 동일, 설치 불필요).
"""
import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVERS_DIR = ROOT / "servers"
DATA = ROOT / "data"
DECOY_LOG = ROOT / "logs" / "honeypatch.log"
RESULT_DIR = ROOT / "tests" / "results"

# 정상 사용자와 공격자를 다른 IP로 흉내 낸다 (비교 화면 web/app.py 와 같은 값).
# 서버 ③이 IP 단위로 공격자를 기억하므로, 이 구분이 없으면 공격 뒤의 정상 요청까지
# 미끼로 보내져 '정상·경계 사례의 오탐 없음'을 확인할 수 없다.
CLIENT_IPS = {"user": "10.0.0.10", "attacker": "10.0.0.66"}

SERVERS = [
    {"id": 1, "mark": "①", "name": "무방비", "script": "vulnerable_server.py", "port": 8001},
    {"id": 2, "mark": "②", "name": "일반 패치", "script": "patched_server.py", "port": 8002},
    {"id": 3, "mark": "③", "name": "허니패치", "script": "honeypatch_server.py", "port": 8003},
]

# ---------------------------------------------------------------------------
# 11주차 고정 검증 사례 3종과 기대 결과 (README 3-2)
#   status      : HTTP 상태 코드
#   verdict     : public(공개 파일) / leak(진짜 비밀 유출) / fake(가짜 파일) / blocked(403)
#   secret_hits : 응답에 들어 있는 '진짜 비밀번호 줄' 개수
#   decoy       : 서버 ③의 미끼 전환 여부 (③에만 적용)
# ---------------------------------------------------------------------------
CASES = [
    {
        "kind": "정상",
        "file": "report.txt",
        "who": "user",
        "point": "보호를 적용해도 정상 사용자가 그대로 파일을 받는지 (②③ 오탐 없음)",
        "expect": {
            1: {"status": 200, "verdict": "public", "secret_hits": 0},
            2: {"status": 200, "verdict": "public", "secret_hits": 0},
            3: {"status": 200, "verdict": "public", "secret_hits": 0, "decoy": False},
        },
    },
    {
        "kind": "위반",
        "file": "../secret/passwords.txt",
        "who": "attacker",
        "point": "①의 진짜 비밀 유출이 ②에서는 차단, ③에서는 가짜 파일로 바뀌는지",
        "expect": {
            1: {"status": 200, "verdict": "leak", "secret_hits": 3},
            2: {"status": 403, "verdict": "blocked", "secret_hits": 0},
            3: {"status": 200, "verdict": "fake", "secret_hits": 0, "decoy": True},
        },
    },
    {
        "kind": "경계",
        "file": "..report.txt",
        "who": "user",
        "point": "이름에 '..'이 있어도 실제 경로가 public 안이면 정상 처리하는지",
        "expect": {
            1: {"status": 200, "verdict": "public", "secret_hits": 0},
            2: {"status": 200, "verdict": "public", "secret_hits": 0},
            3: {"status": 200, "verdict": "public", "secret_hits": 0, "decoy": False},
        },
    },
]

VERDICT_LABEL = {
    "public": "공개 파일",
    "leak": "진짜 비밀 유출",
    "fake": "가짜 파일(미끼)",
    "blocked": "차단(403)",
    "missing": "파일 없음(404)",
    "bad": "잘못된 요청(400)",
    "down": "서버 꺼짐",
    "unknown": "목록에 없는 내용",
}

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 환경 프록시 무시


# ---- 표 출력 보조 (한글은 폭 2칸) ------------------------------------------
def _w(s):
    return sum(2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in str(s))


def pad(s, n):
    s = str(s)
    return s + " " * max(0, n - _w(s))


# ---- 응답 내용 판정 ---------------------------------------------------------
def _files_in(sub):
    """data/<sub> 아래 모든 파일 -> {내용(strip): 상대 경로}"""
    out = {}
    base = DATA / sub
    if base.is_dir():
        for p in base.rglob("*"):
            if p.is_file() and p.name != ".gitkeep":
                try:
                    out[p.read_text("utf-8").strip()] = str(p.relative_to(DATA)).replace("\\", "/")
                except (OSError, UnicodeDecodeError):
                    pass
    return out


def _secret_lines():
    """진짜 비밀 파일에서 주석·빈 줄을 뺀 실제 값 줄"""
    lines = set()
    for text in _files_in("secret"):
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.add(line)
    return lines


def classify(status, body):
    """(상태 코드, 본문) -> (판정 코드, 일치한 파일, 진짜 비밀 줄 수)"""
    hits = sum(1 for line in _secret_lines() if line in body)
    if status is None:
        return "down", None, 0
    if status == 403:
        return "blocked", None, hits
    if status == 404:
        return "missing", None, hits
    if status == 400:
        return "bad", None, hits
    if status != 200:
        return "unknown", None, hits

    text = body.strip()
    for sub, code in (("secret", "leak"), ("decoy", "fake"), ("public", "public")):
        match = _files_in(sub).get(text)
        if match:
            return code, match, hits
    if hits or "SECRET_MARKER" in body:   # 파일 전체와 다르더라도 비밀이 섞였으면 유출
        return "leak", None, hits
    return "unknown", None, hits


# ---- 서버 실행 / 요청 -------------------------------------------------------
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_server(script, port):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen(
        [sys.executable, str(SERVERS_DIR / script), "--port", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    for _ in range(50):
        if proc.poll() is not None:
            raise RuntimeError("서버가 바로 종료됨: %s" % script)
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("서버가 뜨지 않음: %s" % script)


def log_size():
    try:
        return DECOY_LOG.stat().st_size
    except OSError:
        return 0


def ask(server, name, who):
    """서버 하나에 요청 한 번 -> 결과 dict"""
    url = "http://127.0.0.1:%d/download?file=%s" % (server["port"], urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={"X-Forwarded-For": CLIENT_IPS[who]})
    before = log_size() if server["id"] == 3 else 0

    t0 = time.perf_counter()
    try:
        with OPENER.open(req, timeout=10) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        status, raw = None, b""
    ms = (time.perf_counter() - t0) * 1000

    body = raw.decode("utf-8", "replace")
    verdict, matched, hits = classify(status, body)
    out = {"id": server["id"], "mark": server["mark"], "name": server["name"],
           "port": server["port"], "status": status, "ms": round(ms, 1),
           "verdict": verdict, "label": VERDICT_LABEL.get(verdict, verdict),
           "matched": matched, "secret_hits": hits, "decoy": None}
    if server["id"] == 3 and status is not None:
        time.sleep(0.05)  # 로그 쓰기가 응답보다 조금 늦을 수 있음
        out["decoy"] = bool(verdict == "fake" or log_size() > before)
    return out


# ---- 기대값 대조 ------------------------------------------------------------
def check(expect, got):
    """기대값과 실제 결과를 대조 -> 어긋난 항목 목록(비어 있으면 PASS)"""
    diffs = []
    for key in ("status", "verdict", "secret_hits", "decoy"):
        if key not in expect:
            continue
        want, have = expect[key], got.get(key)
        if want != have:
            diffs.append("%s 기대 %s / 실제 %s" % (key, want, have))
    return diffs


def run_fixed_cases(servers, verbose=True):
    """고정 사례 3종을 ①②③에 보내고 PASS/FAIL 판정. -> (결과 목록, 실패 수)"""
    rows, failed = [], 0
    for idx, case in enumerate(CASES, 1):
        results = []
        for s in servers:
            got = ask(s, case["file"], case["who"])
            diffs = check(case["expect"][s["id"]], got)
            got["pass"] = not diffs
            got["diffs"] = diffs
            failed += bool(diffs)
            results.append(got)
        rows.append({"kind": case["kind"], "file": case["file"], "who": case["who"],
                     "ip": CLIENT_IPS[case["who"]], "point": case["point"], "results": results})
        if verbose:
            print_case(idx, rows[-1])
    return rows, failed


def print_case(idx, row):
    who = "정상 사용자" if row["who"] == "user" else "공격자"
    print("[%d/%d] %s 사례  file=%r   보내는 사람: %s (%s)"
          % (idx, len(CASES), row["kind"], row["file"], who, row["ip"]))
    print("      확인: %s" % row["point"])
    head = (pad("서버", 14), pad("코드", 6), pad("응답 내용", 18),
            pad("진짜비밀", 10), pad("미끼전환", 10), pad("시간(ms)", 10), "판정")
    print("      " + " | ".join(head))
    print("      " + "-" * 90)
    for r in row["results"]:
        decoy = "-" if r["decoy"] is None else ("예" if r["decoy"] else "아니요")
        line = (pad("%s %s" % (r["mark"], r["name"]), 14),
                pad(r["status"] if r["status"] is not None else "-", 6),
                pad(r["label"], 18), pad("%d개" % r["secret_hits"], 10), pad(decoy, 10),
                pad(r["ms"], 10), "PASS" if r["pass"] else "FAIL")
        print("      " + " | ".join(line))
        if not r["pass"]:
            print("      ↑ %s %s: %s" % (r["mark"], r["name"], " / ".join(r["diffs"])))
    print()


def print_summary(rows):
    """보호 적용 전(①) -> 일반 패치(②) -> 허니패치(③) 한눈 비교"""
    print("보호 적용 전·후 비교 요약")
    head = (pad("사례", 6), pad("입력(file)", 26), pad("① 무방비", 24),
            pad("② 일반 패치", 24), pad("③ 허니패치", 30))
    print("  " + " | ".join(head))
    print("  " + "-" * 118)
    for row in rows:
        cells = []
        for r in row["results"]:
            cell = "%s %s" % (r["status"] if r["status"] is not None else "-", r["label"])
            if r["id"] == 1 and r["secret_hits"]:
                cell += " %d개" % r["secret_hits"]
            if r["id"] == 3 and r["decoy"] is not None:
                cell += " · 미끼 %s" % ("예" if r["decoy"] else "아니요")
            cells.append(cell)
        print("  " + " | ".join((pad(row["kind"], 6), pad(row["file"], 26),
                                 pad(cells[0], 24), pad(cells[1], 24), pad(cells[2], 30))))
    print()


# ---- 선택 실험: 같은 공격을 여러 번 보내 ① 과 ③ 의 응답 시간 비교 ------------
def timing_experiment(servers, repeat):
    attack = CASES[1]
    print("실험: 위반 사례 %r 를 %d회 반복 — 서버별 응답 모양·시간 비교" % (attack["file"], repeat))
    out = []
    for s in servers:
        times, verdicts = [], set()
        for _ in range(repeat):
            r = ask(s, attack["file"], attack["who"])
            times.append(r["ms"])
            verdicts.add("%s/%s" % (r["status"], r["verdict"]))
        out.append({"id": s["id"], "mark": s["mark"], "name": s["name"], "n": repeat,
                    "avg_ms": round(statistics.mean(times), 2),
                    "median_ms": round(statistics.median(times), 2),
                    "min_ms": round(min(times), 2), "max_ms": round(max(times), 2),
                    "responses": sorted(verdicts)})
    head = (pad("서버", 14), pad("평균(ms)", 10), pad("중앙값(ms)", 12),
            pad("최소", 8), pad("최대", 8), "응답 종류")
    print("  " + " | ".join(head))
    print("  " + "-" * 84)
    for r in out:
        print("  " + " | ".join((pad("%s %s" % (r["mark"], r["name"]), 14), pad(r["avg_ms"], 10),
                                 pad(r["median_ms"], 12), pad(r["min_ms"], 8), pad(r["max_ms"], 8),
                                 ", ".join(r["responses"]))))
    print()
    return out


# ---- 결과 저장 (보고서 근거용) ----------------------------------------------
def save_results(rows, failed, timing, path_md, path_json):
    path_md.parent.mkdir(parents=True, exist_ok=True)
    md = ["# 고정 검증 사례 3종 실행 결과 (서버 ①②③ 비교)", "",
          "- 실행 시각: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
          "- 실행 명령: `python tests/test_cases.py`",
          "- 판정 기준: 11주차 기대 결과표 (README 3-2) — 기대값은 결과에 맞춰 바꾸지 않음",
          "- 결과: **%d/%d 통과**" % (len(CASES) * 3 - failed, len(CASES) * 3), "",
          "| 사례 | 입력(file) | 보내는 사람 | ① 무방비 | ② 일반 패치 | ③ 허니패치 | 판정 |",
          "|---|---|---|---|---|---|---|"]
    for row in rows:
        cells = []
        for r in row["results"]:
            cell = "%s %s" % (r["status"] if r["status"] is not None else "-", r["label"])
            if r["id"] == 1 and r["secret_hits"]:
                cell += " (진짜 비밀번호 %d개)" % r["secret_hits"]
            if r["id"] == 3 and r["decoy"] is not None:
                cell += " · 미끼 전환 %s" % ("예" if r["decoy"] else "아니요")
            cells.append("%s<br>%.1f ms" % (cell, r["ms"]))
        ok = all(r["pass"] for r in row["results"])
        md.append("| %s | `%s` | %s (%s) | %s | %s | %s | %s |"
                  % (row["kind"], row["file"],
                     "정상 사용자" if row["who"] == "user" else "공격자", row["ip"],
                     cells[0], cells[1], cells[2], "PASS" if ok else "**FAIL**"))
    fails = [(row, r) for row in rows for r in row["results"] if not r["pass"]]
    if fails:
        md += ["", "## 기대와 다른 결과", ""]
        for row, r in fails:
            md.append("- %s 사례 / 서버 %s %s: %s"
                      % (row["kind"], r["mark"], r["name"], " / ".join(r["diffs"])))
    if timing:
        md += ["", "## 실험: 위반 사례 반복 요청 응답 시간", "",
               "| 서버 | 횟수 | 평균(ms) | 중앙값(ms) | 최소 | 최대 | 응답 종류 |",
               "|---|---|---|---|---|---|---|"]
        for r in timing:
            md.append("| %s %s | %d | %s | %s | %s | %s | %s |"
                      % (r["mark"], r["name"], r["n"], r["avg_ms"], r["median_ms"],
                         r["min_ms"], r["max_ms"], ", ".join(r["responses"])))
    path_md.write_text("\n".join(md) + "\n", encoding="utf-8")
    path_json.write_text(json.dumps(
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "failed": failed,
         "total": len(CASES) * 3, "cases": rows, "timing": timing},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# ---- 실행 ------------------------------------------------------------------
def main():
    try:        # Windows 터미널에서 한글이 깨지지 않도록
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

    p = argparse.ArgumentParser(description="고정 검증 사례 3종 자동 실행 (서버 ①②③ 비교)")
    p.add_argument("--use-running", action="store_true",
                   help="서버를 직접 띄우지 않고 이미 켜 둔 서버에 요청 (기본 포트 8001/8002/8003)")
    p.add_argument("--s1", type=int, default=8001, help="--use-running 일 때 서버 ① 포트")
    p.add_argument("--s2", type=int, default=8002, help="--use-running 일 때 서버 ② 포트")
    p.add_argument("--s3", type=int, default=8003, help="--use-running 일 때 서버 ③ 포트")
    p.add_argument("--repeat", type=int, default=0, metavar="N",
                   help="위반 사례를 N회 반복해 응답 시간 비교 (0이면 생략)")
    p.add_argument("--no-save", action="store_true", help="결과 파일(tests/results/)을 쓰지 않음")
    a = p.parse_args()

    servers = [dict(s) for s in SERVERS]
    procs = []
    if a.use_running:
        for s, port in zip(servers, (a.s1, a.s2, a.s3)):
            s["port"] = port
        print("이미 켜 둔 서버에 요청합니다 (%s)."
              % ", ".join("%s %d" % (s["mark"], s["port"]) for s in servers))
        print("※ 서버 ③은 공격자 IP를 기억하므로, 앞선 시연 뒤라면 다시 켜고 실행하세요.\n")
    else:
        try:
            for s in servers:
                s["port"] = free_port()
                procs.append(start_server(s["script"], s["port"]))
        except RuntimeError as e:
            for proc in procs:
                proc.terminate()
            print("서버 실행 실패: %s" % e)
            return 2
        print("서버 ①②③을 빈 포트로 띄웠습니다 (%s).\n"
              % ", ".join("%s %d" % (s["mark"], s["port"]) for s in servers))

    DECOY_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        rows, failed = run_fixed_cases(servers)
        print_summary(rows)
        timing = timing_experiment(servers, a.repeat) if a.repeat > 0 else []
    finally:
        for proc in procs:
            proc.terminate()

    total = len(CASES) * 3
    print("결과: %d/%d 통과 (고정 사례 3종 × 서버 3개)" % (total - failed, total))
    if failed:
        print("기대와 다른 항목은 담당자에게 공유하고, 기대값이 아니라 구현·원인을 확인합니다.")
    if not a.no_save:
        md, js = RESULT_DIR / "results.md", RESULT_DIR / "results.json"
        save_results(rows, failed, timing, md, js)
        print("결과 저장: %s , %s" % (md.relative_to(ROOT), js.relative_to(ROOT)))
    return 1 if failed else 0


# pytest 로도 실행할 수 있게 한 함수 (pytest tests/test_cases.py)
def test_fixed_cases():
    servers, procs = [dict(s) for s in SERVERS], []
    try:
        for s in servers:
            s["port"] = free_port()
            procs.append(start_server(s["script"], s["port"]))
        DECOY_LOG.parent.mkdir(parents=True, exist_ok=True)
        rows, failed = run_fixed_cases(servers, verbose=False)
    finally:
        for proc in procs:
            proc.terminate()
    bad = ["%s 사례 / %s%s: %s" % (row["kind"], r["mark"], r["name"], " / ".join(r["diffs"]))
           for row in rows for r in row["results"] if not r["pass"]]
    assert not bad, "기대 결과와 다름 -> " + " | ".join(bad)


if __name__ == "__main__":
    sys.exit(main())
