# -*- coding: utf-8 -*-
"""수정된 버그를 같은 입력으로 수정 전·후 코드에 다시 보내 비교 (이수빈).

    python tests/before_after.py                    # 등록된 버그 전부 (BUGS)
    python tests/before_after.py --bug X4           # 하나만
    python tests/before_after.py --with-fixed       # 끝에 고정 사례 3종(test_cases.py)도 다시 실행
    python tests/before_after.py --with-fixed --label macos   # 결과를 before_after_macos.md 로 따로 저장

하는 일
  1. 버그마다 '수정 전 커밋'의 servers/·data/ 를 임시 폴더에 꺼낸다 (git archive).
     '수정 후'는 지금 작업 폴더의 servers/·data/ 를 임시 폴더에 복사한다.
  2. 두 임시 폴더에서 같은 서버를 빈 포트로 띄우고, 같은 입력을 같은 순서로 보낸다.
  3. 응답 코드·응답 내용(진짜/가짜/공개)·서버 ③ 로그(event, ip)를 나란히 표로 낸다.
  저장소의 서버 코드와 logs/honeypatch.log 는 건드리지 않는다 (로그도 임시 폴더에 쌓임).

버그 추가 방법: 아래 BUGS 에 한 항목을 추가한다.
  before  : 수정 직전 커밋 (git log 로 확인)
  server  : 1/2/3
  steps   : (설명, file 값, X-Forwarded-For 값 또는 None)
  expect  : 단계별 명세상 기대값 dict (status / verdict / event / ip 중 필요한 것만).
            수정 후 결과가 이 값과 같아야 '수정 확인'.
표준 라이브러리만 사용.
"""
import argparse
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cases import RESULT_DIR, ROOT, classify, free_port  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
SCRIPTS = {1: "vulnerable_server.py", 2: "patched_server.py", 3: "honeypatch_server.py"}
ATTACK = "../secret/passwords.txt"

BUGS = [
    {"id": "X4", "found_by": "안지민", "before": "17bd15e",
     "title": "XFF 첫 값이 비어 있으면(',') 빈 문자열 ''을 IP로 기록",
     "fix": "servers/honeypatch_server.py client_ip(): 첫 값이 비면 접속 주소 사용",
     "server": 3,
     "steps": [
         ("XFF=',' 로 공격", ATTACK, ","),
         ("XFF=', 10.0.0.66' 로 공격", ATTACK, ", 10.0.0.66"),
         ("같은 PC가 헤더 없이 report.txt (공격자로 기억됐는지)", "report.txt", None),
     ],
     "expect": [
         {"status": 200, "verdict": "fake", "event": "attack", "ip": "127.0.0.1"},
         {"status": 200, "verdict": "fake", "event": "attack", "ip": "127.0.0.1"},
         {"status": 200, "verdict": "public", "event": "sticky", "ip": "127.0.0.1"},
     ]},
    {"id": "C1-②", "found_by": "이수빈 (코드 검토)", "before": "fd646a0",
     "title": "공개 폴더 이름의 대소문자만 바꾼 정상 요청을 public 밖으로 판정 (macOS)",
     "fix": "servers/patched_server.py check_path(): 문자열로 밖이면 상위 폴더가 public과 같은 폴더인지 samefile로 재확인",
     "server": 2, "only_if": "case_insensitive",
     "steps": [("공개 폴더 대소문자만 바꿔 요청", "../PUBLIC/report.txt", "10.0.0.10")],
     "expect": [{"status": 200, "verdict": "public"}]},
    {"id": "C1-③", "found_by": "이수빈 (코드 검토)", "before": "fd646a0",
     "title": "같은 요청을 서버 ③이 공격으로 기록하고 그 사용자를 sticky로 기억 (macOS)",
     "fix": "위와 같음 (서버 ③은 서버 ②의 check_path()를 사용)",
     "server": 3, "only_if": "case_insensitive",
     "steps": [("공개 폴더 대소문자만 바꿔 요청", "../PUBLIC/report.txt", "10.0.0.10"),
               ("같은 사용자가 report.txt (오탐으로 기억됐는지)", "report.txt", "10.0.0.10")],
     "expect": [{"status": 200, "verdict": "public", "event": None},
                {"status": 200, "verdict": "public", "event": None}]},
]


def case_insensitive():
    """대소문자를 구분하지 않으면서 realpath가 대소문자를 맞춰 주지 않는 환경인지 (macOS 기본 APFS).
    Windows는 realpath가 실제 대소문자로 바꿔 주므로 이 버그가 재현되지 않는다."""
    with tempfile.TemporaryDirectory() as t:
        real = os.path.join(t, "Ab")
        os.mkdir(real)
        alt = os.path.join(t, "aB")
        return os.path.exists(alt) and os.path.realpath(alt) != os.path.realpath(real)


CONDITIONS = {"case_insensitive": (case_insensitive,
                                   "대소문자를 구분하지 않고 realpath가 대소문자를 맞추지 않는 환경(macOS)에서만 재현")}


# ---- 코드 꺼내기 ------------------------------------------------------------
def extract_commit(commit, dest):
    out = subprocess.run(["git", "archive", "--format=tar", commit, "servers", "data", "logs"],
                         cwd=ROOT, capture_output=True)
    if out.returncode != 0:
        msg = out.stderr.decode(errors="replace").strip()
        if "not a valid object" in msg or "unknown revision" in msg:
            msg += ("\n  -> 이 PC 저장소에 수정 전 커밋 %s 이 없습니다. 최신 코드를 받지 않은 상태일 수 있으니 "
                    "`git pull` 후 다시 실행하세요. (확인: git log --oneline -5)" % commit)
        raise RuntimeError("git archive 실패 (%s): %s" % (commit, msg))
    with tarfile.open(fileobj=io.BytesIO(out.stdout)) as tf:
        if hasattr(tarfile, "data_filter"):   # Python 3.12+ 경고 방지
            tf.extractall(dest, filter="data")
        else:
            tf.extractall(dest)
    (Path(dest) / "logs").mkdir(exist_ok=True)


def copy_worktree(dest):
    for sub in ("servers", "data"):
        shutil.copytree(ROOT / sub, Path(dest) / sub,
                        ignore=shutil.ignore_patterns("__pycache__", "gen_*.txt"))
    (Path(dest) / "logs").mkdir(exist_ok=True)


def commit_label(commit):
    out = subprocess.run(["git", "log", "-1", "--format=%h %s", commit], cwd=ROOT,
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    return (out.stdout or "").strip() or commit


def worktree_label():
    head = commit_label("HEAD")
    dirty = subprocess.run(["git", "status", "--porcelain", "servers"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
    return "작업 폴더 (HEAD %s%s)" % (head.split()[0], ", servers 수정 있음" if dirty else "")


# ---- 실행 ------------------------------------------------------------------
def start(tree, server):
    port = free_port()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen([sys.executable, str(Path(tree) / "servers" / SCRIPTS[server]),
                             "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    for _ in range(50):
        if proc.poll() is not None:
            raise RuntimeError("서버가 바로 종료됨: %s" % tree)
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return proc, port
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("서버가 뜨지 않음: %s" % tree)


def log_entries(tree):
    p = Path(tree) / "logs" / "honeypatch.log"
    try:
        return [json.loads(l) for l in p.read_text("utf-8").splitlines() if l.strip()]
    except OSError:
        return []


def send(port, name, xff):
    url = "http://127.0.0.1:%d/download?file=%s" % (port, urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={} if xff is None else {"X-Forwarded-For": xff})
    try:
        with OPENER.open(req, timeout=10) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        status, raw = None, b""
    verdict, _, hits = classify(status, raw.decode("utf-8", "replace"))
    return status, verdict, hits


def run_version(tree, bug):
    proc, port = start(tree, bug["server"])
    rows = []
    try:
        for desc, name, xff in bug["steps"]:
            before = len(log_entries(tree))
            status, verdict, hits = send(port, name, xff)
            time.sleep(0.05)
            new = log_entries(tree)[before:]
            rows.append({"status": status, "verdict": verdict, "secret_hits": hits,
                         "event": new[-1]["event"] if new else None,
                         "ip": new[-1]["ip"] if new else None})
    finally:
        proc.terminate()
        proc.wait()
    return rows


def fmt(r, keys):
    out = []
    for k in keys:
        v = r.get(k)
        out.append("%s=%s" % (k, "-" if v is None else (repr(v) if k == "ip" else v)))
    return ", ".join(out)


def mismatches(expect, got):
    return ["%s 기대 %r / 실제 %r" % (k, v, got.get(k)) for k, v in expect.items() if got.get(k) != v]


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    p = argparse.ArgumentParser(description="수정된 버그를 같은 입력으로 수정 전·후 비교")
    p.add_argument("--bug", action="append", help="버그 번호만 골라 실행 (여러 번 가능)")
    p.add_argument("--with-fixed", action="store_true", help="고정 사례 3종(test_cases.py)도 다시 실행")
    p.add_argument("--label", help="결과 파일 이름 뒤에 붙일 이름 (예: macos -> before_after_macos.md)")
    p.add_argument("--no-save", action="store_true")
    a = p.parse_args()

    bugs = [b for b in BUGS if not a.bug or b["id"] in a.bug]
    if not bugs:
        print("실행할 버그가 없습니다. BUGS 목록을 확인하세요.")
        return 2

    report, all_ok = [], True
    for bug in bugs:
        cond = bug.get("only_if")
        if cond and not CONDITIONS[cond][0]():
            print("[%s] %s\n   => 건너뜀: %s (이 PC: %s)\n" % (bug["id"], bug["title"], CONDITIONS[cond][1], sys.platform))
            report.append({"id": bug["id"], "found_by": bug["found_by"], "title": bug["title"],
                           "fix": bug["fix"], "skipped": CONDITIONS[cond][1]})
            continue
        with tempfile.TemporaryDirectory() as t_before, tempfile.TemporaryDirectory() as t_after:
            extract_commit(bug["before"], t_before)
            copy_worktree(t_after)
            before = run_version(t_before, bug)
            after = run_version(t_after, bug)
        steps = []
        for (desc, name, xff), exp, b, af in zip(bug["steps"], bug["expect"], before, after):
            mb, ma = mismatches(exp, b), mismatches(exp, af)
            steps.append({"desc": desc, "file": name, "xff": xff, "expect": exp,
                          "before": b, "after": af,
                          "before_ok": not mb, "after_ok": not ma, "after_diffs": ma})
        reproduced = any(not s["before_ok"] for s in steps)   # 수정 전 코드에서 버그가 재현되는가
        fixed = all(s["after_ok"] for s in steps)             # 수정 후 코드가 명세대로인가
        all_ok &= reproduced and fixed
        report.append({"id": bug["id"], "found_by": bug["found_by"], "title": bug["title"],
                       "fix": bug["fix"], "before_label": commit_label(bug["before"]),
                       "after_label": worktree_label(), "steps": steps,
                       "reproduced_before": reproduced, "fixed_after": fixed})

        keys = list(bug["expect"][0])
        print("[%s] %s (발견: %s)" % (bug["id"], bug["title"], bug["found_by"]))
        print("     수정 전: %s" % commit_label(bug["before"]))
        print("     수정 후: %s" % worktree_label())
        for s in steps:
            print("   - %s  file=%r XFF=%r" % (s["desc"], s["file"], s["xff"]))
            print("       기대   : %s" % fmt(s["expect"], keys))
            print("       수정 전: %s  %s" % (fmt(s["before"], keys), "" if s["before_ok"] else "← 명세와 다름"))
            print("       수정 후: %s  %s" % (fmt(s["after"], keys), "" if s["after_ok"] else "← 명세와 다름"))
        print("   => 수정 전 버그 재현: %s / 수정 후 명세대로: %s\n"
              % ("예" if reproduced else "아니요", "예" if fixed else "아니요"))

    fixed_cases = None
    if a.with_fixed:
        out = subprocess.run([sys.executable, str(ROOT / "tests" / "test_cases.py"), "--no-save"],
                             cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
        last = [l for l in out.stdout.splitlines() if l.startswith("결과:")]
        fixed_cases = last[-1] if last else "실행 실패"
        print("고정 사례 3종 (수정 후 코드): %s" % fixed_cases)
        all_ok &= out.returncode == 0

    if not a.no_save:
        save(report, fixed_cases, a)
    return 0 if all_ok else 1


def save(report, fixed_cases, a):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    md = ["# 수정된 버그 — 같은 입력으로 수정 전·후 재실행 (이수빈)", "",
          "- 실행 시각: %s" % time.strftime("%Y-%m-%d %H:%M:%S"),
          "- 실행 명령: `python tests/before_after.py%s%s%s`" % (
              "".join(" --bug %s" % b for b in (a.bug or [])),
              " --with-fixed" if fixed_cases else "", " --label %s" % a.label if a.label else ""),
          "- Python: %s / OS: %s" % (sys.version.split()[0], sys.platform)]
    if fixed_cases:
        md.append("- 고정 사례 3종 (수정 후 코드): %s" % fixed_cases)
    for r in report:
        if r.get("skipped"):
            md += ["", "## %s — %s (발견: %s)" % (r["id"], r["title"], r["found_by"]), "",
                   "- 수정 내용: %s" % r["fix"], "- **건너뜀**: %s (실행 OS: %s)" % (r["skipped"], sys.platform)]
            continue
        keys = list(r["steps"][0]["expect"])
        md += ["", "## %s — %s (발견: %s)" % (r["id"], r["title"], r["found_by"]), "",
               "- 수정 내용: %s" % r["fix"],
               "- 수정 전: `%s`" % r["before_label"], "- 수정 후: %s" % r["after_label"],
               "- 수정 전 버그 재현: **%s** / 수정 후 명세대로: **%s**"
               % ("예" if r["reproduced_before"] else "아니요", "예" if r["fixed_after"] else "아니요"), "",
               "| 단계 | file | XFF | 기대 (명세) | 수정 전 | 수정 후 |", "|---|---|---|---|---|---|"]
        for s in r["steps"]:
            md.append("| %s | `%s` | %s | %s | %s%s | %s%s |" % (
                s["desc"], s["file"], "(없음)" if s["xff"] is None else "`%r`" % s["xff"],
                fmt(s["expect"], keys),
                fmt(s["before"], keys), "" if s["before_ok"] else " ✗",
                fmt(s["after"], keys), "" if s["after_ok"] else " ✗"))
    name = "before_after" + ("_" + a.label if a.label else "")
    (RESULT_DIR / (name + ".md")).write_text("\n".join(md) + "\n", encoding="utf-8")
    (RESULT_DIR / (name + ".json")).write_text(json.dumps(
        {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "fixed_cases": fixed_cases, "bugs": report},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("결과 저장: tests/results/%s.md, .json" % name)


if __name__ == "__main__":
    sys.exit(main())
