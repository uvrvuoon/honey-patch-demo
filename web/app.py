"""비교 웹 화면 서버 (이수빈).

같은 요청을 서버 ①②③에 동시에 보내고, 응답을 나란히 보여 주는 화면을 띄운다.
브라우저가 세 포트에 직접 요청하면 CORS에 막히므로 이 서버가 대신 요청한다.

    python web/app.py            # -> http://127.0.0.1:8000

판정(진짜 유출 / 차단 / 가짜 파일 / 미끼 전환)은 공격자가 받는 응답이 아니라
방어자 쪽 정보로 한다.
  - 응답 본문을 data/public, data/secret, data/decoy 의 실제 파일 내용과 비교
  - 서버 ③의 공격 로그 파일(기본 logs/honeypatch.log)에 요청 중 새 줄이 생겼는지 확인

표준 라이브러리만 사용 (설치 불필요).
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
INDEX_HTML = Path(__file__).resolve().parent / "index.html"
SECRET_MARKER = "SECRET_MARKER"
BODY_LIMIT = 4000  # 화면에 보여 줄 응답 본문 최대 글자 수

# 정상 사용자와 공격자를 다른 IP로 흉내 낸다 (X-Forwarded-For 헤더).
# 이 화면은 모든 요청을 127.0.0.1에서 보내므로, 이 헤더가 없으면
# 서버 ③이 공격 이후의 정상 요청까지 같은 공격자로 보고 미끼로 보낼 수 있다.
CLIENT_IPS = {"user": "10.0.0.10", "attacker": "10.0.0.66"}

SERVERS = [  # (id, 이름, 포트) - 포트는 실행 옵션으로 바꿀 수 있음
    {"id": 1, "name": "무방비 서버", "port": 8001},
    {"id": 2, "name": "일반 패치 서버", "port": 8002},
    {"id": 3, "name": "허니패치 서버", "port": 8003},
]
DECOY_LOG = ROOT / "logs" / "honeypatch.log"

# 환경 변수의 프록시 설정을 무시하고 로컬 서버에 바로 연결
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ---- 파일 내용 대조 -------------------------------------------------------
def _read_dir(sub):
    """data/<sub> 아래 모든 파일 -> {내용: 상대 경로}"""
    found = {}
    base = DATA / sub
    if base.is_dir():
        for p in base.rglob("*"):
            if p.is_file() and p.name != ".gitkeep":
                try:
                    found[p.read_text("utf-8").strip()] = str(p.relative_to(DATA)).replace("\\", "/")
                except (OSError, UnicodeDecodeError):
                    pass
    return found


def _secret_lines():
    """진짜 비밀 파일의 실제 값 줄 (주석 제외)"""
    lines = set()
    for text in _read_dir("secret"):
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.add(line)
    return lines


def classify(status, body):
    """응답 -> (판정 코드, 설명, 일치한 파일, 진짜 비밀 줄 수)"""
    secret_hits = sum(1 for line in _secret_lines() if line in body)
    if status is None:
        return "down", "서버 꺼짐", None, 0
    if status == 403:
        return "blocked", "차단 (403)", None, 0
    if status == 404:
        return "missing", "파일 없음 (404)", None, 0
    if status == 400:
        return "bad", "잘못된 요청 (400)", None, 0
    if status != 200:
        return "other", "응답 %d" % status, None, secret_hits

    text = body.strip()
    for sub, code, label in (("secret", "leak", "진짜 비밀 유출"),
                             ("decoy", "fake", "가짜 파일 (미끼)"),
                             ("public", "public", "공개 파일 (정상)")):
        match = _read_dir(sub).get(text)
        if match:
            return code, label, match, secret_hits
    if secret_hits or SECRET_MARKER in body:
        return "leak", "진짜 비밀 유출", None, secret_hits
    return "unknown", "목록에 없는 내용", None, 0


# ---- 서버 ③ 공격 로그 ----------------------------------------------------
def log_size():
    try:
        return DECOY_LOG.stat().st_size
    except OSError:
        return 0


def read_log(offset):
    """offset(바이트) 이후 새 줄 목록과 새 offset"""
    try:
        with open(DECOY_LOG, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            if offset > end:  # 로그가 지워지거나 새로 만들어진 경우
                offset = 0
            f.seek(offset)
            chunk = f.read()
    except OSError:
        return [], 0, False
    # 마지막 줄이 아직 다 안 써졌으면 다음 번에 읽는다
    cut = chunk.rfind(b"\n") + 1
    lines = chunk[:cut].decode("utf-8", "replace").splitlines()
    entries = []
    for line in lines:
        if not line.strip():
            continue
        try:
            entries.append({"json": json.loads(line)})
        except ValueError:
            entries.append({"raw": line})
    return entries, offset + cut, True


# ---- 세 서버에 요청 -------------------------------------------------------
def ask(server, name, who):
    url = "http://127.0.0.1:%d/download?file=%s" % (server["port"], urllib.parse.quote(name, safe=""))
    req = urllib.request.Request(url, headers={"X-Forwarded-For": CLIENT_IPS[who]})
    log_before = log_size() if server["id"] == 3 else 0
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

    verdict, label, matched, hits = classify(status, body)
    result = {
        "id": server["id"], "name": server["name"], "port": server["port"],
        "status": status, "ms": round(ms, 1),
        "body": body[:BODY_LIMIT], "truncated": len(body) > BODY_LIMIT,
        "verdict": verdict, "label": label, "matched": matched, "secret_hits": hits,
        "decoy": None,  # ①② 에는 미끼가 없음
    }
    if server["id"] == 3:
        # 미끼 전환 판단: 가짜 파일을 받았거나, 요청 사이에 공격 로그가 늘었으면 전환
        time.sleep(0.05)  # 로그 쓰기가 응답보다 조금 늦을 수 있음
        if status is not None:
            result["decoy"] = verdict == "fake" or log_size() > log_before
    return result


# ---- HTTP ---------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(url.query, keep_blank_values=True)

        if url.path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML.read_bytes(), "text/html; charset=utf-8")

        if url.path == "/api/compare":
            name = (q.get("file") or [""])[0]
            who = (q.get("as") or ["user"])[0]
            if not name or who not in CLIENT_IPS:
                return self._json(400, {"error": "file 값과 as=user|attacker 가 필요합니다"})
            with ThreadPoolExecutor(len(SERVERS)) as pool:
                results = list(pool.map(lambda s: ask(s, name, who), SERVERS))
            return self._json(200, {"file": name, "as": who, "ip": CLIENT_IPS[who],
                                    "time": time.strftime("%H:%M:%S"), "results": results})

        if url.path == "/api/status":
            out = []
            for s in SERVERS:
                try:
                    OPENER.open("http://127.0.0.1:%d/" % s["port"], timeout=0.5).close()
                    up = True
                except urllib.error.HTTPError:
                    up = True  # 404라도 응답했으면 켜져 있음
                except (urllib.error.URLError, OSError):
                    up = False
                out.append({"id": s["id"], "port": s["port"], "up": up})
            return self._json(200, {"servers": out})

        if url.path == "/api/decoy-log":
            try:
                offset = int((q.get("offset") or ["0"])[0])
            except ValueError:
                offset = 0
            entries, new_offset, exists = read_log(offset)
            return self._json(200, {"entries": entries, "offset": new_offset, "exists": exists,
                                    "path": str(DECOY_LOG.relative_to(ROOT)).replace("\\", "/")})

        self._send(404, b"not found\n", "text/plain; charset=utf-8")

    def _json(self, status, obj):
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _send(self, status, body, ctype):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        if "/api/" not in self.path:  # 주기적 상태 확인 요청은 출력하지 않음
            sys.stderr.write("[web] %s\n" % (fmt % args))


def main():
    global DECOY_LOG
    p = argparse.ArgumentParser(description="①②③ 비교 웹 화면")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--s1", type=int, default=8001, help="서버 ① 포트")
    p.add_argument("--s2", type=int, default=8002, help="서버 ② 포트")
    p.add_argument("--s3", type=int, default=8003, help="서버 ③ 포트")
    p.add_argument("--decoy-log", default=str(DECOY_LOG), help="서버 ③ 공격 로그 파일")
    a = p.parse_args()
    for s, port in zip(SERVERS, (a.s1, a.s2, a.s3)):
        s["port"] = port
    DECOY_LOG = Path(a.decoy_log).resolve()

    httpd = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    print("[web] 비교 화면: http://127.0.0.1:%d" % a.port, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
