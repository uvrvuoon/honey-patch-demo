# -*- coding: utf-8 -*-
"""13주차: 서버 ①(무방비)과 ③(허니패치)의 응답 시간 차이 (이수빈).

    python tests/timing_1_vs_3.py                      # 기본: 200회 × 3라운드, 워밍업 5회
    python tests/timing_1_vs_3.py --repeat 50 --rounds 1   # 빠른 시험 실행

질문: 공격자가 응답 시간만 보고 ③(허니패치)을 ①(무방비)과 구분할 수 있는가?
      (원논문 7절: 응답 시간은 허니패치가 들키는 경로. 원논문은 공격 요청에 약 0.25초 지연)

설계
  - 측정 대상 5종을 '한 바퀴'로 묶어, 바퀴마다 순서를 섞어(시드 13 고정) 번갈아 보낸다.
    한쪽만 몰아서 재면 그 사이 PC 상태 변화가 서버 차이처럼 보이기 때문.
        ① 공격  ../secret/passwords.txt (10.0.0.66)
        ② 공격  ../secret/passwords.txt (10.0.0.66)   ← 참고용
        ③ 공격  ../secret/passwords.txt (10.0.0.66)
        ① 정상  report.txt (10.0.0.10)
        ③ 정상  report.txt (10.0.0.10)                 ← ③ 내부에서 공격·정상 차이(로그 쓰기 비용) 확인용
  - 라운드마다 서버 ①②③을 새로 띄움. 앞의 W바퀴는 워밍업으로 버림.
  - 대표값은 중앙값. 라운드별 중앙값을 따로 내서 '라운드 간 흔들림'과 비교한다.
  - 응답 내용도 매번 검사 (① 공격=진짜 유출, ③ 공격=가짜, 정상=공개 파일). 다르면 이상 응답.

기대 결과 (실행 전 작성, 결과에 맞춰 고치지 않음)
  E1. ③ 공격과 ① 공격의 중앙값 차이는 1ms 미만 (원논문의 프로세스 복제·메모리 치환 단계가 없음)
  E2. 이상 응답 0
  (③ 공격이 ① 공격보다 '항상' 느린지, 즉 차이가 라운드 간 흔들림보다 큰지는 기대값 없이 관찰만 함)

끝나면 logs/honeypatch.log 를 실행 전 상태로 되돌린다.
결과: tests/results/timing_1_vs_3.md, tests/results/timing_1_vs_3.json
"""
import argparse
import json
import platform
import random
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cases import DECOY_LOG, RESULT_DIR, ROOT, classify, free_port, start_server  # noqa: E402

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ATTACK = "../secret/passwords.txt"
SCRIPTS = {1: "vulnerable_server.py", 2: "patched_server.py", 3: "honeypatch_server.py"}
SERIES = [  # (이름, 서버, file, XFF, 기대 판정)
    ("① 공격", 1, ATTACK, "10.0.0.66", "leak"),
    ("② 공격", 2, ATTACK, "10.0.0.66", "blocked"),
    ("③ 공격", 3, ATTACK, "10.0.0.66", "fake"),
    ("① 정상", 1, "report.txt", "10.0.0.10", "public"),
    ("③ 정상", 3, "report.txt", "10.0.0.10", "public"),
]
E1_LIMIT_MS = 1.0


def once(port, name, xff):
    url = "http://127.0.0.1:%d/download?file=%s" % (port, urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={"X-Forwarded-For": xff})
    t0 = time.perf_counter()
    try:
        with OPENER.open(req, timeout=10) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError):
        status, raw = None, b""
    ms = (time.perf_counter() - t0) * 1000
    return ms, classify(status, raw.decode("utf-8", "replace"))[0]


def summary(xs):
    xs = sorted(xs)
    return {"n": len(xs), "median": round(statistics.median(xs), 3),
            "mean": round(statistics.mean(xs), 3),
            "p95": round(xs[min(len(xs) - 1, int(len(xs) * 0.95))], 3),
            "min": round(xs[0], 3), "max": round(xs[-1], 3)}


def commit():
    try:
        h = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
                           capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "servers"], cwd=ROOT,
                               capture_output=True, text=True, encoding="utf-8", errors="replace").stdout.strip()
        return h + (" (servers 수정됨)" if dirty else "")
    except OSError:
        return "?"


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    p = argparse.ArgumentParser(description="서버 ① vs ③ 응답 시간 비교")
    p.add_argument("--repeat", type=int, default=200, help="라운드당 측정 바퀴 수 (기본 200)")
    p.add_argument("--rounds", type=int, default=3, help="라운드 수 (기본 3)")
    p.add_argument("--warmup", type=int, default=5, help="버리는 바퀴 수 (기본 5)")
    p.add_argument("--no-save", action="store_true")
    a = p.parse_args()

    rng = random.Random(13)
    DECOY_LOG.parent.mkdir(parents=True, exist_ok=True)
    log_backup = DECOY_LOG.read_bytes() if DECOY_LOG.exists() else None
    t_start = time.time()
    raw = {s[0]: [] for s in SERIES}               # 전체
    per_round = []                                  # 라운드별 중앙값
    anomalies = {s[0]: 0 for s in SERIES}
    try:
        for rnd in range(1, a.rounds + 1):
            ports, procs = {}, []
            try:
                for sid, script in SCRIPTS.items():
                    ports[sid] = free_port()
                    procs.append(start_server(script, ports[sid]))
                rtimes = {s[0]: [] for s in SERIES}
                for lap in range(a.warmup + a.repeat):
                    order = SERIES[:]
                    rng.shuffle(order)
                    for name, sid, f, xff, want in order:
                        ms, verdict = once(ports[sid], f, xff)
                        if lap < a.warmup:
                            continue
                        rtimes[name].append(ms)
                        if verdict != want:
                            anomalies[name] += 1
            finally:
                for pr in procs:
                    pr.terminate()
                    pr.wait()
            med = {k: round(statistics.median(v), 3) for k, v in rtimes.items()}
            per_round.append(med)
            for k, v in rtimes.items():
                raw[k].extend(v)
            print("라운드 %d 중앙값(ms): %s" % (rnd, ", ".join("%s %.3f" % kv for kv in med.items())))
    finally:
        if log_backup is None:
            if DECOY_LOG.exists():
                DECOY_LOG.unlink()
        else:
            DECOY_LOG.write_bytes(log_backup)

    total = {k: summary(v) for k, v in raw.items()}
    diffs = [round(m["③ 공격"] - m["① 공격"], 3) for m in per_round]
    diffs_in3 = [round(m["③ 공격"] - m["③ 정상"], 3) for m in per_round]
    swing = {k: round(max(m[k] for m in per_round) - min(m[k] for m in per_round), 3) for k in raw}
    overall_diff = round(total["③ 공격"]["median"] - total["① 공격"]["median"], 3)
    e1 = abs(overall_diff) < E1_LIMIT_MS
    e2 = sum(anomalies.values()) == 0
    always_slower = all(d > 0 for d in diffs)
    beyond_swing = min(diffs) > max(swing["① 공격"], swing["③ 공격"]) if diffs else False

    print()
    for k, s in total.items():
        print("  %-6s 중앙값 %.3f  평균 %.3f  p95 %.3f  최소 %.3f  최대 %.3f  이상 응답 %d"
              % (k, s["median"], s["mean"], s["p95"], s["min"], s["max"], anomalies[k]))
    print()
    print("E1 ③공격−①공격 중앙값 차이 %.3f ms (기대 < %.1f ms) -> %s"
          % (overall_diff, E1_LIMIT_MS, "기대대로" if e1 else "기대와 다름"))
    print("E2 이상 응답 %d (기대 0) -> %s" % (sum(anomalies.values()), "기대대로" if e2 else "기대와 다름"))
    print("관찰: 라운드별 ③−① 차이 %s ms, 라운드 간 흔들림 ① %.3f / ③ %.3f ms"
          % (diffs, swing["① 공격"], swing["③ 공격"]))
    print("관찰: 모든 라운드에서 ③이 느림: %s / 차이가 흔들림보다 큼: %s" % (always_slower, beyond_swing))
    print("관찰: ③ 내부 공격−정상 차이(로그 쓰기 비용 추정) %s ms" % diffs_in3)
    print("소요 %.1f초" % (time.time() - t_start))

    if not a.no_save:
        cond = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "os": platform.platform(),
                "python": sys.version.split()[0], "commit": commit(),
                "command": "python tests/timing_1_vs_3.py --repeat %d --rounds %d --warmup %d"
                           % (a.repeat, a.rounds, a.warmup)}
        save(cond, total, per_round, anomalies, diffs, diffs_in3, swing, overall_diff,
             e1, e2, always_slower, beyond_swing)
    return 0 if (e1 and e2) else 1


def save(cond, total, per_round, anomalies, diffs, diffs_in3, swing, overall_diff,
         e1, e2, always_slower, beyond_swing):
    RESULT_DIR.mkdir(parents=True, exist_ok=True)
    md = ["# 서버 ① vs ③ 응답 시간 (같은 공격) — 이수빈", "",
          "- 실행 시각: %s" % cond["time"], "- OS: %s" % cond["os"],
          "- Python: %s / 커밋: %s" % (cond["python"], cond["commit"]),
          "- 실행 명령: `%s`" % cond["command"],
          "- 방법: 5종 요청을 한 바퀴로 묶어 순서를 섞어 번갈아 전송, 라운드마다 서버 새로 실행, 대표값 중앙값", "",
          "## 전체", "",
          "| 요청 | 횟수 | 중앙값(ms) | 평균 | p95 | 최소 | 최대 | 이상 응답 |",
          "|---|---|---|---|---|---|---|---|"]
    for k, s in total.items():
        md.append("| %s | %d | %.3f | %.3f | %.3f | %.3f | %.3f | %d |"
                  % (k, s["n"], s["median"], s["mean"], s["p95"], s["min"], s["max"], anomalies[k]))
    md += ["", "## 라운드별 중앙값(ms)", "",
           "| 라운드 | " + " | ".join(total) + " | ③공격−①공격 | ③공격−③정상 |",
           "|---|" + "---|" * (len(total) + 2)]
    for i, m in enumerate(per_round, 1):
        md.append("| %d | %s | %.3f | %.3f |" % (i, " | ".join("%.3f" % m[k] for k in total),
                                                diffs[i - 1], diffs_in3[i - 1]))
    md.append("| 라운드 간 흔들림 | %s | | |" % " | ".join("%.3f" % swing[k] for k in total))
    md += ["", "## 판정", "",
           "| 항목 | 기대 (실행 전) | 실제 | 결과 |", "|---|---|---|---|",
           "| E1 ③공격−①공격 중앙값 차이 | < %.1f ms | %.3f ms | %s |"
           % (E1_LIMIT_MS, overall_diff, "일치" if e1 else "**불일치**"),
           "| E2 이상 응답 | 0 | %d | %s |" % (sum(anomalies.values()), "일치" if e2 else "**불일치**"),
           "| (관찰) 모든 라운드에서 ③이 느림 | - | %s | - |" % ("예" if always_slower else "아니요"),
           "| (관찰) 차이가 라운드 간 흔들림보다 큼 | - | %s | - |" % ("예" if beyond_swing else "아니요")]
    (RESULT_DIR / "timing_1_vs_3.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (RESULT_DIR / "timing_1_vs_3.json").write_text(json.dumps(
        {"conditions": cond, "summary": total, "per_round_median": per_round,
         "anomalies": anomalies, "diff_3_minus_1": diffs, "diff_3attack_minus_3normal": diffs_in3,
         "round_swing": swing, "overall_diff": overall_diff,
         "E1": e1, "E2": e2, "always_slower": always_slower, "beyond_swing": beyond_swing},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("결과 저장: tests/results/timing_1_vs_3.md, .json")


if __name__ == "__main__":
    sys.exit(main())
