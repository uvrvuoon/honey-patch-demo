# -*- coding: utf-8 -*-
"""14주차 실험: 가짜 파일 수에 따른 서버 ③ 응답 시간 측정 (윤아란).

    python tests/bench.py                          # 기본: 10/100/1000개 × 200회 × 3라운드
    python tests/bench.py --counts 10 100 --repeat 50 --rounds 1   # 빠른 시험 실행
    python tests/bench.py --no-save                # 결과 파일을 쓰지 않음

실험 설계 (docs/experiment_plan.md)
  - 변수: 미끼 폴더(data/decoy/secret)의 추가 가짜 파일 수 — 10 / 100 / 1000
          (기본 미끼 passwords.txt 1개는 항상 유지. 그 외 조건은 모두 고정)
  - 지표: 서버 ③ 응답 시간(ms), 대표값은 중앙값. 평균·p95·최소·최대도 함께 기록
  - 요청 3종(조건마다 같은 순서로 번갈아 보냄)
        정상       file=report.txt                 정상 사용자 10.0.0.10
        공격       file=../secret/passwords.txt    공격자 10.0.0.66
        공격후정상 file=report.txt                 공격자 10.0.0.66 (sticky 상태)
  - 반복: 조건마다 워밍업 W회(버림) + 측정 R회. 전체를 K라운드 반복하며
          라운드마다 조건 순서를 섞어(시드 고정) 순서 효과를 줄인다.
  - 조건마다 서버 ③을 새로 띄운다 (공격자 기억·캐시 초기화).
  - 응답 시간만 보지 않고 응답 내용도 검사한다: 공격은 가짜 passwords.txt,
    정상·공격후정상은 공개 report.txt여야 하며, 다르면 '이상 응답'으로 센다.

끝나면 생성 파일을 지우고 logs/honeypatch.log를 실행 전 상태로 되돌린다.
결과: tests/results/bench.md (보고서용 표), tests/results/bench.json (원자료 포함)
표준 라이브러리만 사용.
"""
import argparse
import json
import os
import platform
import random
import signal
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import make_decoys                                   # noqa: E402
from test_cases import free_port, start_server       # noqa: E402  (김진하 코드 재사용)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
DECOY_LOG = ROOT / "logs" / "honeypatch.log"
RESULT_DIR = ROOT / "tests" / "results"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))

REQUESTS = [  # (이름, file 값, X-Forwarded-For, 기대 응답 파일)
    ("정상", "report.txt", "10.0.0.10", DATA / "public" / "report.txt"),
    ("공격", "../secret/passwords.txt", "10.0.0.66", DATA / "decoy" / "secret" / "passwords.txt"),
    ("공격후정상", "report.txt", "10.0.0.66", DATA / "public" / "report.txt"),
]


def request_once(port, name, ip):
    url = "http://127.0.0.1:%d/download?file=%s" % (port, urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={"X-Forwarded-For": ip})
    t0 = time.perf_counter()
    try:
        with OPENER.open(req, timeout=10) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        status, raw = None, b""
    return (time.perf_counter() - t0) * 1000, status, raw


def summarize(times):
    s = sorted(times)
    p95 = s[min(len(s) - 1, int(round(0.95 * (len(s) - 1))))]
    return {"n": len(s), "median": round(statistics.median(s), 3),
            "mean": round(statistics.mean(s), 3), "p95": round(p95, 3),
            "min": round(s[0], 3), "max": round(s[-1], 3),
            "stdev": round(statistics.stdev(s), 3) if len(s) > 1 else 0.0}


def run_condition(count, warmup, repeat, expected):
    """가짜 파일 count개 상태에서 서버 ③을 새로 띄워 요청 3종을 측정"""
    make_decoys.make(count)
    port = free_port()
    proc = start_server("honeypatch_server.py", port)
    times = {r[0]: [] for r in REQUESTS}
    bad = {r[0]: 0 for r in REQUESTS}
    try:
        for i in range(warmup + repeat):
            for label, name, ip, _ in REQUESTS:
                ms, status, raw = request_once(port, name, ip)
                if i < warmup:
                    continue
                times[label].append(ms)
                if status != 200 or raw.strip() != expected[label]:
                    bad[label] += 1
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    return times, bad


def git_commit():
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(ROOT),
                             capture_output=True, text=True, timeout=5)
        head = out.stdout.strip() or "?"
        dirty = subprocess.run(["git", "status", "--porcelain", "servers"], cwd=str(ROOT),
                               capture_output=True, text=True, timeout=5).stdout.strip()
        return head + (" (servers/ 수정 있음)" if dirty else "")
    except (OSError, subprocess.SubprocessError):
        return "?"


def environment(a):
    return {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "os": platform.platform(), "python": platform.python_version(),
            "machine": platform.machine(), "cpu_count": os.cpu_count(),
            "commit": git_commit(),
            "command": "python " + " ".join(["tests/bench.py"] + sys.argv[1:]),
            "counts": a.counts, "warmup": a.warmup, "repeat": a.repeat,
            "rounds": a.rounds, "seed": a.seed}


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    ap = argparse.ArgumentParser(description="가짜 파일 수에 따른 서버 ③ 응답 시간 측정")
    ap.add_argument("--counts", type=int, nargs="+", default=[10, 100, 1000],
                    help="추가 가짜 파일 수 목록 (기본 10 100 1000)")
    ap.add_argument("--repeat", type=int, default=200, help="조건·요청별 측정 횟수 (기본 200)")
    ap.add_argument("--warmup", type=int, default=5, help="버리는 워밍업 횟수 (기본 5)")
    ap.add_argument("--rounds", type=int, default=3, help="전체 반복 라운드 수 (기본 3)")
    ap.add_argument("--seed", type=int, default=14, help="라운드별 조건 순서 섞기 시드")
    ap.add_argument("--no-save", action="store_true", help="결과 파일을 쓰지 않음")
    a = ap.parse_args()

    # 강제 종료(SIGTERM)에도 finally가 실행되어 생성 파일 삭제·로그 복구가 되도록
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(130))

    env = environment(a)
    print("실행 조건: %s | Python %s | commit %s" % (env["os"], env["python"], env["commit"]))
    print("변수: 가짜 파일 수 %s | 측정 %d회(+워밍업 %d) × %d라운드\n"
          % (a.counts, a.repeat, a.warmup, a.rounds))

    expected = {label: path.read_bytes().strip() for label, _, _, path in REQUESTS}
    DECOY_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_backup = DECOY_LOG.read_bytes() if DECOY_LOG.exists() else None
    leftover = len(make_decoys.generated())
    if leftover:
        print("※ 이전 생성 파일 %d개가 남아 있어 조건에 맞게 다시 맞춥니다.\n" % leftover)

    rnd = random.Random(a.seed)
    samples = {c: {r[0]: [] for r in REQUESTS} for c in a.counts}
    anomalies = {c: {r[0]: 0 for r in REQUESTS} for c in a.counts}
    per_round = []
    t_start = time.perf_counter()
    try:
        for k in range(1, a.rounds + 1):
            order = list(a.counts)
            rnd.shuffle(order)
            print("라운드 %d/%d  순서 %s" % (k, a.rounds, order))
            for c in order:
                times, bad = run_condition(c, a.warmup, a.repeat, expected)
                row = {"round": k, "count": c}
                for label in times:
                    samples[c][label] += times[label]
                    anomalies[c][label] += bad[label]
                    row[label] = round(statistics.median(times[label]), 3)
                per_round.append(row)
                print("  가짜 %5d개  중앙값(ms) %s"
                      % (c, "  ".join("%s %.3f" % (l, row[l]) for l in times)))
    finally:
        make_decoys.clean()
        if log_backup is None:
            if DECOY_LOG.exists():
                DECOY_LOG.unlink()
        else:
            DECOY_LOG.write_bytes(log_backup)
    elapsed = time.perf_counter() - t_start

    summary = {c: {l: summarize(samples[c][l]) for l in samples[c]} for c in a.counts}
    print("\n요약 (전체 라운드 합산, 단위 ms)")
    print("  %-8s %-10s %8s %8s %8s %8s %8s  이상응답"
          % ("가짜수", "요청", "중앙값", "평균", "p95", "최소", "최대"))
    for c in a.counts:
        for l, s in summary[c].items():
            print("  %-8d %-10s %8.3f %8.3f %8.3f %8.3f %8.3f  %d"
                  % (c, l, s["median"], s["mean"], s["p95"], s["min"], s["max"], anomalies[c][l]))
    print("\n소요 시간: %.1f초 | 생성 파일 삭제·로그 원상복구 완료" % elapsed)

    if not a.no_save:
        save(env, summary, anomalies, per_round, samples, elapsed)
    return 1 if any(v for c in anomalies.values() for v in c.values()) else 0


def save(env, summary, anomalies, per_round, samples, elapsed):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    labels = [r[0] for r in REQUESTS]
    md = ["# 14주차 실험: 가짜 파일 수에 따른 서버 ③ 응답 시간", "",
          "| 항목 | 값 |", "|---|---|",
          "| 실행 시각 | %s |" % env["time"],
          "| OS | %s (%s, CPU %s개) |" % (env["os"], env["machine"], env["cpu_count"]),
          "| Python | %s |" % env["python"],
          "| 커밋 | %s |" % env["commit"],
          "| 명령어 | `%s` |" % env["command"],
          "| 변수 | 추가 가짜 파일 수 %s (기본 미끼 1개 별도) |" % env["counts"],
          "| 반복 | 조건·요청별 %d회 측정(+워밍업 %d회 제외) × %d라운드, 순서 섞기 시드 %d |"
          % (env["repeat"], env["warmup"], env["rounds"], env["seed"]),
          "| 대표값 | 중앙값 |",
          "| 소요 시간 | %.1f초 |" % elapsed, "",
          "## 요약 (전체 라운드 합산, ms)", "",
          "| 가짜 파일 수 | 요청 | n | 중앙값 | 평균 | p95 | 최소 | 최대 | 표준편차 | 이상 응답 |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for c, rows in summary.items():
        for l in labels:
            s = rows[l]
            md.append("| %d | %s | %d | **%.3f** | %.3f | %.3f | %.3f | %.3f | %.3f | %d |"
                      % (c, l, s["n"], s["median"], s["mean"], s["p95"], s["min"],
                         s["max"], s["stdev"], anomalies[c][l]))
    md += ["", "## 라운드별 중앙값 (ms) — 라운드 간 흔들림 확인용", "",
           "| 라운드 | 가짜 파일 수 | " + " | ".join(labels) + " |",
           "|---|---|" + "---|" * len(labels)]
    for r in per_round:
        md.append("| %d | %d | %s |" % (r["round"], r["count"],
                                         " | ".join("%.3f" % r[l] for l in labels)))
    md += ["", "- 이상 응답: 상태 코드가 200이 아니거나, 공격에 가짜 passwords.txt가 아닌 내용 / "
           "정상·공격후정상에 공개 report.txt가 아닌 내용이 온 횟수"]
    (RESULT_DIR / "bench.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (RESULT_DIR / "bench.json").write_text(json.dumps(
        {"env": env, "elapsed_s": round(elapsed, 2), "summary": summary,
         "anomalies": anomalies, "per_round": per_round,
         "samples_ms": {c: {l: [round(x, 3) for x in v] for l, v in d.items()}
                        for c, d in samples.items()}},
        ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print("결과 저장: tests/results/bench.md , tests/results/bench.json")


if __name__ == "__main__":
    sys.exit(main())
