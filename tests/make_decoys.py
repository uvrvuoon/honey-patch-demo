# -*- coding: utf-8 -*-
"""14주차 실험용 가짜 파일(미끼) 생성·삭제 (윤아란).

    python tests/make_decoys.py --count 100    # 생성 파일을 정확히 100개로 맞춤
    python tests/make_decoys.py --clean        # 생성 파일 모두 삭제
    python tests/make_decoys.py --status       # 현재 생성 파일 수 확인

- 생성 위치: data/decoy/secret/gen_0001.txt ... (서버 ③의 기본 미끼 passwords.txt와 같은 폴더)
  → '미끼 폴더 안 파일 수'가 실험 변수가 되도록 같은 폴더에 만든다.
- 기본 미끼 data/decoy/secret/passwords.txt 는 건드리지 않는다 (고정 사례 3종 유지).
- 파일 이름 접두어 gen_ 로 구분하며 .gitignore에 등록되어 Git에 올라가지 않는다.
- 내용은 passwords.txt와 같은 형식의 가짜 계정 목록. 파일 번호를 시드로 써서
  같은 번호는 항상 같은 내용이 나온다 (재현성).
표준 라이브러리만 사용.
"""
import argparse
import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GEN_DIR = ROOT / "data" / "decoy" / "secret"
PREFIX = "gen_"

_NAMES = ["admin", "dbuser", "backup", "deploy", "monitor", "ops", "dev", "test",
          "svc", "report", "audit", "jenkins", "mysql", "web", "mail", "ftp"]
_PW_CHARS = string.ascii_letters + string.digits + "!@#$%^&*()_+"


def _content(idx):
    rnd = random.Random(idx)
    lines = ["# account list (internal use only)", "# format: user:password"]
    for _ in range(rnd.randint(4, 8)):
        user = rnd.choice(_NAMES) + (str(rnd.randint(1, 99)) if rnd.random() < 0.5 else "")
        pw = "".join(rnd.choice(_PW_CHARS) for _ in range(rnd.randint(10, 16)))
        lines.append("%s:%s" % (user, pw))
    return "\n".join(lines) + "\n"


def generated():
    """현재 생성 파일 목록 (번호순)"""
    return sorted(GEN_DIR.glob(PREFIX + "*.txt"))


def clean():
    n = 0
    for p in generated():
        p.unlink()
        n += 1
    return n


def make(count):
    """생성 파일 수를 정확히 count개로 맞춘다 (남는 것은 지우고 모자란 것은 만든다)."""
    if count < 0:
        raise ValueError("count는 0 이상")
    GEN_DIR.mkdir(parents=True, exist_ok=True)
    want = {"%s%04d.txt" % (PREFIX, i) for i in range(1, count + 1)}
    for p in generated():
        if p.name not in want:
            p.unlink()
    for name in sorted(want):
        p = GEN_DIR / name
        if not p.exists():
            p.write_text(_content(int(name[len(PREFIX):-4])), encoding="utf-8")
    return len(generated())


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, OSError):
        pass
    ap = argparse.ArgumentParser(description="14주차 실험용 가짜 파일 생성·삭제")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--count", type=int, metavar="N", help="생성 파일 수를 N개로 맞춤")
    g.add_argument("--clean", action="store_true", help="생성 파일 모두 삭제")
    g.add_argument("--status", action="store_true", help="현재 생성 파일 수 출력")
    a = ap.parse_args()
    if a.clean:
        print("삭제: %d개 (%s)" % (clean(), GEN_DIR.relative_to(ROOT)))
    elif a.status:
        print("현재 생성 파일: %d개 (%s)" % (len(generated()), GEN_DIR.relative_to(ROOT)))
    else:
        print("생성 파일: %d개 (%s)" % (make(a.count), GEN_DIR.relative_to(ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
