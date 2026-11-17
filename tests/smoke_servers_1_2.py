"""서버 ①·② 동작 확인용 스모크 테스트 (저장소 루트에서 실행).

    python tests/smoke_servers_1_2.py

두 서버를 빈 포트로 띄운 뒤 같은 입력을 보내 상태 코드와 비밀 유출 여부를 비교한다.
기대값과 다르면 종료 코드 1. (11주차 고정 사례 3종 + 추가 확인용 입력)
"""
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVERS = os.path.join(ROOT, "servers")
SECRET_ABS = os.path.join(ROOT, "data", "secret", "passwords.txt")
MARKER = "SECRET_MARKER"

# (분류, 설명, file 값, 서버① 기대 코드, 서버② 기대 코드)
CASES = [
    ("정상", "고정 사례: 공개 파일", "report.txt", 200, 200),
    ("위반", "고정 사례: 상위 경로 이탈", "../secret/passwords.txt", 200, 403),
    ("경계", "고정 사례: '..'으로 시작하는 정상 파일", "..report.txt", 200, 200),
    ("추가", "'..' 포함이지만 실제로는 public 안", "../public/report.txt", 200, 200),
    ("추가", "절대 경로로 비밀 파일 지정", SECRET_ABS, 200, 403),
    ("추가", "이탈 후 존재하지 않는 파일", "../secret/none.txt", 404, 403),
    ("추가", "public 안 존재하지 않는 파일", "nope.txt", 404, 404),
    ("추가", "널 바이트 삽입", "report.txt\x00.png", 400, 400),
]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start(script):
    port = free_port()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.Popen([sys.executable, os.path.join(SERVERS, script), "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return proc, port
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start: " + script)


def get(port, name):
    url = "http://127.0.0.1:%d/download?file=%s" % (port, urllib.parse.quote(name, safe=""))
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main():
    (p1, port1), (p2, port2) = start("vulnerable_server.py"), start("patched_server.py")
    failed = 0
    try:
        print("%-4s | %-34s | %-9s | %-9s | %s" % ("분류", "입력(file)", "서버①", "서버②", "판정"))
        print("-" * 80)
        for kind, desc, name, exp1, exp2 in CASES:
            c1, b1 = get(port1, name)
            c2, b2 = get(port2, name)
            leak1 = " 유출" if MARKER in b1 else ""
            leak2 = " 유출" if MARKER in b2 else ""
            ok = c1 == exp1 and c2 == exp2 and not leak2
            failed += not ok
            shown = name.replace("\x00", "%00") if name != SECRET_ABS else "<절대경로>/secret/passwords.txt"
            print("%-4s | %-34s | %-9s | %-9s | %s" % (
                kind, shown, str(c1) + leak1, str(c2) + leak2, "OK" if ok else "FAIL (기대 %d/%d)" % (exp1, exp2)))
    finally:
        p1.terminate()
        p2.terminate()
    print("-" * 80)
    print("결과: %d/%d 통과" % (len(CASES) - failed, len(CASES)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
