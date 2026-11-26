# -*- coding: utf-8 -*-
"""13주차 추가 검증 사례 — 표기 변형 입력 (김진하).

같은 공격을 다른 모양으로 적어서 보냈을 때 ①②③의 판정이 흔들리는지 본다.
    경로 구분자(`..\\`), URL 인코딩(1회·2회·대문자 16진수), 대소문자,
    절대 경로, 빈 값, 널 바이트, 경로 중간의 `..`

    python tests/test_encoding_cases.py              # 서버 ①②③을 직접 띄워 실행
    python tests/test_encoding_cases.py --use-running --s1 8001 --s2 8002 --s3 8003

규칙
- 11주차 고정 사례 3종(tests/test_cases.py)은 건드리지 않는다. 추가 사례는 이 파일로 분리한다.
- 기대값(EXPECT)은 실행 전에 작성했고, 실행 결과에 맞춰 고치지 않는다.
- 기대값은 README 6절 명세(② 실제 경로가 public 밖이면 403 / ③ public 밖이면 미끼 파일,
  없으면 404)와 "정상 사용자는 막히면 안 된다"를 기준으로 쓴다.

OS 의존성 (기대값을 실행 환경에 따라 나누는 이유 — 실행 전에 정해 둔 규칙)
- `\\`가 경로 구분자인지: Windows는 구분자, Linux/macOS는 이름에 쓸 수 있는 보통 글자
- 파일 시스템이 대소문자를 구분하는지: Windows·macOS(기본 APFS)는 구분 안 함, Linux는 구분함
  → 두 속성을 실행 시작 때 확인해서 그 조합에 해당하는 기대값을 쓴다.
    결과에 맞춰 고르는 것이 아니라, 환경 속성으로 미리 갈라 둔 표를 고르는 것이다.

판정 재사용: 응답 내용 판정(classify)과 서버 실행은 tests/test_cases.py 것을 그대로 쓴다.
표준 라이브러리만 사용한다.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cases import (  # noqa: E402
    CLIENT_IPS, DATA, DECOY_LOG, RESULT_DIR, ROOT, SERVERS, VERDICT_LABEL,
    classify, free_port, pad, start_server,
)

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
SECRET_ABS = str((ROOT / "data" / "secret" / "passwords.txt").resolve())

# ---- 실행 환경 속성 (기대값 분기 기준) --------------------------------------
BACKSLASH_IS_SEP = os.sep == "\\" or os.altsep == "\\"
CASE_INSENSITIVE = (DATA / "public" / "REPORT.TXT").exists()  # report.txt 가 대문자로도 열리면 구분 안 함

# ---------------------------------------------------------------------------
# 추가 검증 사례
#   send="quote" : 보통처럼 URL 인코딩해서 보냄
#   send="raw"   : 적은 글자 그대로 보냄 (인코딩 자체를 시험하는 사례용)
#   who          : user(10.0.0.10) / attacker(10.0.0.66)  — 서버 ③의 IP 기억 때문에 구분
# ---------------------------------------------------------------------------
CASES = [
    {"id": "E1", "group": "경로 구분자", "value": "..\\secret\\passwords.txt", "send": "quote",
     "who": "attacker", "point": "Windows 경로 구분자 `\\`로 쓴 경로 이탈"},
    {"id": "E2", "group": "URL 인코딩", "value": "%2e%2e%2fsecret%2fpasswords.txt", "send": "raw",
     "who": "attacker", "point": "`../`를 1회 인코딩 (서버가 한 번 해제하면 위반 사례와 같아짐)"},
    {"id": "E3", "group": "URL 인코딩", "value": "%252e%252e%252fsecret%252fpasswords.txt", "send": "raw",
     "who": "attacker", "point": "2중 인코딩 (한 번만 해제되므로 `%2e%2e%2f…` 라는 이름의 파일이 됨)"},
    {"id": "E4", "group": "대소문자", "value": "../SECRET/PASSWORDS.TXT", "send": "quote",
     "who": "attacker", "point": "같은 비밀 파일을 대문자로 지정"},
    {"id": "E5", "group": "절대 경로", "value": SECRET_ABS, "send": "quote",
     "who": "attacker", "point": "public 기준 상대 경로가 아니라 절대 경로로 지정"},
    {"id": "E6", "group": "빈 값", "value": "", "send": "raw",
     "who": "user", "point": "file 값이 비어 있을 때"},
    {"id": "E7", "group": "경로 중간 ..", "value": "public/../public/report.txt", "send": "quote",
     "who": "user", "point": "`..`가 중간에 있지만 정규화하면 public 안 (없는 파일)"},
    {"id": "E8", "group": "경로 중간 ..", "value": "../public/report.txt", "send": "quote",
     "who": "user", "point": "`..`가 있어도 결국 public 안의 정상 파일 (오탐 확인)"},
    {"id": "E9", "group": "널 바이트", "value": "report.txt%00.png", "send": "raw",
     "who": "user", "point": "널 바이트로 확장자 검사를 속이는 고전 수법"},
    {"id": "E10", "group": "URL 인코딩", "value": "%2E%2E%2Fsecret%2Fpasswords.txt", "send": "raw",
     "who": "attacker", "point": "인코딩의 16진수를 대문자로 (%2E vs %2e)"},
]

# ---- 기대값 (실행 전 작성) ---------------------------------------------------
# 서버별로 {status, verdict, secret_hits} / 서버 ③은 decoy 까지.
# verdict: public(공개 파일) / leak(진짜 비밀 유출) / fake(가짜 파일) / blocked(403)
#          / missing(404) / bad(400)
LEAK = {"status": 200, "verdict": "leak", "secret_hits": 3}
BLOCKED = {"status": 403, "verdict": "blocked", "secret_hits": 0}
FAKE = {"status": 200, "verdict": "fake", "secret_hits": 0, "decoy": True}
PUBLIC = {"status": 200, "verdict": "public", "secret_hits": 0}
MISSING = {"status": 404, "verdict": "missing", "secret_hits": 0}
BAD = {"status": 400, "verdict": "bad", "secret_hits": 0}


def _no_decoy(d):
    return dict(d, decoy=False)


def _with_decoy(d, flag):
    return dict(d, decoy=flag)


def expectations():
    """환경 속성(BACKSLASH_IS_SEP, CASE_INSENSITIVE)에 따른 기대값 표."""
    e = {}

    # E1 `..\secret\passwords.txt`
    if BACKSLASH_IS_SEP:   # Windows: 경로 이탈이 성립
        e["E1"] = {1: LEAK, 2: BLOCKED, 3: FAKE}
    else:                  # Linux/macOS: 통째로 하나의 파일 이름 -> public 안, 그런 파일 없음
        e["E1"] = {1: MISSING, 2: MISSING, 3: _no_decoy(MISSING)}

    # E2 / E10 1회 인코딩 -> 서버가 한 번 해제 -> 위반 사례와 동일
    e["E2"] = {1: LEAK, 2: BLOCKED, 3: FAKE}
    e["E10"] = {1: LEAK, 2: BLOCKED, 3: FAKE}

    # E3 2중 인코딩 -> `%2e%2e%2fsecret%2fpasswords.txt` 라는 이름의 파일 (public 안, 없음)
    e["E3"] = {1: MISSING, 2: MISSING, 3: _no_decoy(MISSING)}

    # E4 대소문자: 실제 경로는 항상 public 밖 -> ②는 어디서나 403.
    #    ①과 ③은 파일 시스템이 대소문자를 구분하는지에 따라 갈린다.
    #    ③은 어느 쪽이든 '공격'으로 판정해 로그를 남기므로 decoy=True.
    if CASE_INSENSITIVE:
        e["E4"] = {1: LEAK, 2: BLOCKED, 3: FAKE}
    else:
        e["E4"] = {1: MISSING, 2: BLOCKED, 3: _with_decoy(MISSING, True)}

    # E5 절대 경로: 이어 붙이면 절대 경로가 이김 -> public 밖
    e["E5"] = {1: LEAK, 2: BLOCKED, 3: FAKE}

    # E6 빈 값 / E9 널 바이트: 경로 판정 전에 400
    e["E6"] = {1: BAD, 2: BAD, 3: _no_decoy(BAD)}
    e["E9"] = {1: BAD, 2: BAD, 3: _no_decoy(BAD)}

    # E7 정규화하면 data/public/public/report.txt (public 안, 없는 파일)
    e["E7"] = {1: MISSING, 2: MISSING, 3: _no_decoy(MISSING)}

    # E8 정규화하면 data/public/report.txt (정상 파일) -> 셋 다 그대로 줘야 하고 미끼 전환 없음
    e["E8"] = {1: PUBLIC, 2: PUBLIC, 3: _no_decoy(PUBLIC)}
    return e


EXPECT = expectations()


# ---- 요청 ------------------------------------------------------------------
def log_size():
    try:
        return DECOY_LOG.stat().st_size
    except OSError:
        return 0


def request(server, case):
    """사례 하나를 서버 하나에 보낸다."""
    value = case["value"]
    sent = value if case["send"] == "raw" else urllib.parse.quote(value, safe="")
    url = "http://127.0.0.1:%d/download?file=%s" % (server["port"], sent)
    req = urllib.request.Request(url, headers={"X-Forwarded-For": CLIENT_IPS[case["who"]]})
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
           "sent": sent, "status": status, "ms": round(ms, 1), "verdict": verdict,
           "label": VERDICT_LABEL.get(verdict, verdict), "matched": matched,
           "secret_hits": hits, "decoy": None}
    if server["id"] == 3 and status is not None:
        time.sleep(0.05)   # 로그 쓰기가 응답보다 조금 늦을 수 있음
        out["decoy"] = bool(verdict == "fake" or log_size() > before)
    return out


def check(expect, got):
    diffs = []
    for key in ("status", "verdict", "secret_hits", "decoy"):
        if key not in expect:
            continue
        if expect[key] != got.get(key):
            diffs.append("%s 기대 %s / 실제 %s" % (key, expect[key], got.get(key)))
    return diffs


# ---- 실행 ------------------------------------------------------------------
def run(servers, restart3=None):
    """restart3: 사례마다 서버 ③을 새로 띄우는 함수 (사례 간 간섭 제거용). None이면 한 번만 띄운 채로 진행."""
    rows, failed = [], 0
    for idx, case in enumerate(CASES, 1):
        if restart3 is not None:
            restart3()
        results = []
        for s in servers:
            got = request(s, case)
            diffs = check(EXPECT[case["id"]][s["id"]], got)
            got["pass"] = not diffs
            got["diffs"] = diffs
            failed += bool(diffs)
            results.append(got)
        row = dict(case, results=results, ip=CLIENT_IPS[case["who"]])
        rows.append(row)
        print_case(idx, row)
    return rows, failed


def print_case(idx, row):
    who = "정상 사용자" if row["who"] == "user" else "공격자"
    print("[%d/%d] %s  (%s)  file=%r   보내는 사람: %s (%s)"
          % (idx, len(CASES), row["id"], row["group"], row["value"], who, row["ip"]))
    print("       노림수: %s" % row["point"])
    print("       " + " | ".join((pad("서버", 14), pad("코드", 6), pad("응답 내용", 18),
                                  pad("진짜비밀", 10), pad("미끼전환", 10), pad("시간(ms)", 10), "판정")))
    print("       " + "-" * 90)
    for r in row["results"]:
        decoy = "-" if r["decoy"] is None else ("예" if r["decoy"] else "아니요")
        print("       " + " | ".join((
            pad("%s %s" % (r["mark"], r["name"]), 14),
            pad(r["status"] if r["status"] is not None else "-", 6),
            pad(r["label"], 18), pad("%d개" % r["secret_hits"], 10), pad(decoy, 10),
            pad(r["ms"], 10), "일치" if r["pass"] else "불일치")))
        if not r["pass"]:
            print("       ↑ %s %s: %s" % (r["mark"], r["name"], " / ".join(r["diffs"])))
    print()


def print_summary(rows, failed):
    print("요약 — 표기만 바꾼 입력에서 ①②③의 판정")
    print("  " + " | ".join((pad("번호", 6), pad("입력", 40), pad("① 무방비", 20),
                             pad("② 일반 패치", 20), pad("③ 허니패치", 26))))
    print("  " + "-" * 120)
    for row in rows:
        cells = []
        for r in row["results"]:
            c = "%s %s" % (r["status"] if r["status"] is not None else "-", r["label"])
            if r["id"] == 1 and r["secret_hits"]:
                c += " %d개" % r["secret_hits"]
            if r["id"] == 3 and r["decoy"] is not None:
                c += " · 미끼 %s" % ("예" if r["decoy"] else "아니요")
            cells.append(c)
        value = row["value"] if len(row["value"]) <= 38 else row["value"][:18] + "…" + row["value"][-18:]
        print("  " + " | ".join((pad(row["id"], 6), pad(value, 40), pad(cells[0], 20),
                                 pad(cells[1], 20), pad(cells[2], 26))))
    print()
    total = len(CASES) * 3
    print("결과: %d/%d 기대와 일치 (사례 %d개 × 서버 3개)" % (total - failed, total, len(CASES)))
    bad = [(row, r) for row in rows for r in row["results"] if not r["pass"]]
    if bad:
        print("반례 후보 %d건:" % len(bad))
        for row, r in bad:
            print("  - %s (%s) / 서버 %s %s: %s" % (row["id"], row["value"], r["mark"], r["name"],
                                                    " / ".join(r["diffs"])))
    else:
        print("반례 없음 — 위 입력들에서는 표기를 바꿔도 ①②③의 판정이 기대와 같았다.")
    print()


# ---- 결과 저장 --------------------------------------------------------------
def git_info():
    def run_git(*args):
        try:
            return subprocess.run(["git"] + list(args), cwd=str(ROOT), capture_output=True,
                                  text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return "?"
    head = run_git("rev-parse", "--short", "HEAD")
    dirty = bool(run_git("status", "--porcelain", "--", "servers", "data"))
    return head + (" (servers/·data/ 수정됨)" if dirty else "")


def save(rows, failed, md_path, json_path, fresh):
    md_path.parent.mkdir(parents=True, exist_ok=True)
    env = ("| 항목 | 값 |\n|---|---|\n"
           "| 실행 시각 | %s |\n| 실행 명령 | `python tests/test_encoding_cases.py%s` |\n"
           "| 실행 모드 | %s |\n"
           "| OS | %s |\n| Python | %s |\n| 커밋 | %s |\n"
           "| `\\\\`가 경로 구분자 | %s |\n| 파일 시스템 대소문자 구분 | %s |\n"
           % (time.strftime("%Y-%m-%d %H:%M:%S"), " --fresh" if fresh else "",
              "사례마다 서버 ③ 새로 실행 (사례 간 간섭 없음)" if fresh
              else "서버 ③을 한 번만 띄운 채로 10개 사례 연속 전송",
              sys.platform, sys.version.split()[0], git_info(),
              "예 (Windows 기대값 적용)" if BACKSLASH_IS_SEP else "아니요 (Linux/macOS 기대값 적용)",
              "아니요 (대소문자 구분 안 함)" if CASE_INSENSITIVE else "예 (구분함)"))

    total = len(CASES) * 3
    md = ["# 추가 검증 사례 — 표기 변형 입력 (서버 ①②③ 비교, 김진하)", "", env,
          "- 기대값은 실행 전에 작성했고 결과에 맞춰 바꾸지 않았다.",
          "- 기대값은 실행 환경 속성(위 두 줄)에 따라 미리 갈라 둔 표에서 고른다.",
          "- 11주차 고정 사례 3종은 `tests/test_cases.py` 에 그대로 두고 건드리지 않았다.",
          "- 결과: **%d/%d 기대와 일치**" % (total - failed, total), "",
          "| 번호 | 입력 (`file=`) | 노림수 | 보내는 사람 | ① 무방비 | ② 일반 패치 | ③ 허니패치 | 결과 |",
          "|---|---|---|---|---|---|---|---|"]
    for row in rows:
        cells = []
        for r in row["results"]:
            c = "%s %s" % (r["status"] if r["status"] is not None else "-", r["label"])
            if r["id"] == 1 and r["secret_hits"]:
                c += " (진짜 비밀번호 %d개)" % r["secret_hits"]
            if r["id"] == 3 and r["decoy"] is not None:
                c += " · 미끼 %s" % ("예" if r["decoy"] else "아니요")
            cells.append(c)
        ok = all(r["pass"] for r in row["results"])
        md.append("| %s | `%s` | %s | %s | %s | %s | %s | %s |"
                  % (row["id"], row["value"].replace("|", "\\|") or "(빈 값)", row["point"],
                     "정상 사용자" if row["who"] == "user" else "공격자",
                     cells[0], cells[1], cells[2], "일치" if ok else "**불일치**"))

    bad = [(row, r) for row in rows for r in row["results"] if not r["pass"]]
    md += ["", "## 반례", ""]
    if bad:
        md += ["| 번호 | 입력 | 서버 | 기대 | 실제 |", "|---|---|---|---|---|"]
        for row, r in bad:
            md.append("| %s | `%s` | %s %s | %s | %s |"
                      % (row["id"], row["value"], r["mark"], r["name"],
                         EXPECT[row["id"]][r["id"]], " / ".join(r["diffs"])))
    else:
        md.append("없음. 위 입력들에서는 표기를 바꿔도 ①②③의 판정이 실행 전 기대와 같았다. "
                  "(시험한 입력과 근거는 위 표)")

    md_path.write_text("\n".join(md) + "\n", encoding="utf-8", newline="\n")
    json_path.write_text(json.dumps(
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "platform": sys.platform,
         "python": sys.version.split()[0], "commit": git_info(),
         "backslash_is_sep": BACKSLASH_IS_SEP, "case_insensitive": CASE_INSENSITIVE,
         "failed": failed, "total": total,
         "expect": {k: {str(i): v for i, v in d.items()} for k, d in EXPECT.items()},
         "cases": rows}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass

    p = argparse.ArgumentParser(description="추가 검증 사례 — 표기 변형 입력")
    p.add_argument("--use-running", action="store_true", help="이미 켜 둔 서버에 요청")
    p.add_argument("--fresh", action="store_true",
                   help="사례마다 서버 ③을 새로 띄워 앞 사례의 영향(공격자 IP 기억)을 없앰")
    p.add_argument("--s1", type=int, default=8001)
    p.add_argument("--s2", type=int, default=8002)
    p.add_argument("--s3", type=int, default=8003)
    p.add_argument("--no-save", action="store_true", help="결과 파일을 쓰지 않음")
    a = p.parse_args()

    print("실행 환경: `\\` 경로 구분자 = %s / 파일 시스템 대소문자 구분 = %s"
          % ("예" if BACKSLASH_IS_SEP else "아니요", "아니요" if CASE_INSENSITIVE else "예"))
    print("→ 이 조합에 해당하는 기대값 표를 사용합니다.\n")

    servers = [dict(s) for s in SERVERS]
    procs = []
    if a.use_running:
        for s, port in zip(servers, (a.s1, a.s2, a.s3)):
            s["port"] = port
        print("이미 켜 둔 서버에 요청합니다. 서버 ③은 다시 켜고 실행하세요.\n")
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

    restart3 = None
    if a.fresh:
        if a.use_running:
            print("--fresh 는 서버를 직접 띄울 때만 쓸 수 있습니다.")
            return 2

        def restart3():                      # noqa: F811  (조건부 정의)
            if procs and procs[-1] is not None:
                procs[-1].terminate()
                time.sleep(0.15)
            port = free_port()
            servers[2]["port"] = port
            procs[-1] = start_server(servers[2]["script"], port)
        print("--fresh: 사례마다 서버 ③을 새로 띄웁니다 (공격자 기억이 빈 상태로 시작).\n")

    DECOY_LOG.parent.mkdir(parents=True, exist_ok=True)
    backup = DECOY_LOG.read_bytes() if DECOY_LOG.exists() else None
    try:
        rows, failed = run(servers, restart3)
        print_summary(rows, failed)
    finally:
        for proc in procs:
            proc.terminate()
        time.sleep(0.2)
        if backup is None:          # 실행 전 상태로 되돌린다
            if DECOY_LOG.exists():
                DECOY_LOG.unlink()
        else:
            DECOY_LOG.write_bytes(backup)

    if not a.no_save:
        stem = "encoding_results_fresh" if a.fresh else "encoding_results"
        md, js = RESULT_DIR / (stem + ".md"), RESULT_DIR / (stem + ".json")
        save(rows, failed, md, js, a.fresh)
        print("결과 저장: %s , %s" % (md.relative_to(ROOT), js.relative_to(ROOT)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
