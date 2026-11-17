"""서버 ①·②(그리고 ③ 허니패치)가 함께 쓰는 HTTP 처리 뼈대.

각 서버는 DownloadHandler를 상속해 resolve(name)만 구현하면 된다.
  - resolve()가 파일 경로(str)를 돌려주면 그 파일을 읽어 200으로 응답
  - resolve()가 Blocked 예외를 던지면 403으로 응답
"""
import argparse
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
PUBLIC_DIR = DATA_DIR / "public"   # 다운로드가 허용된 유일한 디렉터리
SECRET_DIR = DATA_DIR / "secret"   # 공격자가 노리는 비밀 파일 위치


class Blocked(Exception):
    """요청 경로가 허용 범위 밖이라 거부할 때 사용. args[0]에 실제 경로."""


class DownloadHandler(BaseHTTPRequestHandler):
    tag = "server"  # 로그 구분용 이름 (하위 클래스에서 덮어씀)

    def resolve(self, name):
        raise NotImplementedError

    # ---- 요청 처리 -------------------------------------------------------
    def do_GET(self):
        url = urlsplit(self.path)
        if url.path != "/download":
            return self._reply(404, "not found\n")

        values = parse_qs(url.query, keep_blank_values=True).get("file")
        if not values or values[0] == "":
            return self._reply(400, "bad request: missing 'file' parameter\n")
        name = values[0]  # parse_qs가 %2e%2e%2f 같은 URL 인코딩을 한 번 해제함
        if "\x00" in name:  # 널 바이트는 경로 함수에서 예외를 일으키므로 미리 거부
            return self._reply(400, "bad request: invalid file name\n")

        try:
            path = self.resolve(name)
        except Blocked as e:
            self._defense_log("BLOCK", name, e.args[0] if e.args else "?")
            return self._reply(403, "forbidden: requested path is outside public\n")

        try:
            with open(path, "rb") as f:
                body = f.read()
        except ValueError:  # 널 바이트 등 잘못된 경로 문자
            self._defense_log("BAD", name, path)
            return self._reply(400, "bad request: invalid file name\n")
        except OSError:     # 없음 / 디렉터리 / 권한 없음
            self._defense_log("MISS", name, path)
            return self._reply(404, "file not found\n")

        self._defense_log("SERVE", name, path)
        self._reply(200, body)

    # ---- 보조 ------------------------------------------------------------
    def _reply(self, status, body):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _defense_log(self, decision, name, path):
        # 방어자(서버) 내부 판정 로그. 공격자가 받는 응답과 구분해 stderr로만 출력
        sys.stderr.write("[%s] %-5s file=%r -> %s\n" % (self.tag, decision, name, path))

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s - %s\n" % (self.tag, self.address_string(), fmt % args))


def run(handler_cls, default_port):
    p = argparse.ArgumentParser(description=handler_cls.tag)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=default_port)
    a = p.parse_args()
    httpd = ThreadingHTTPServer((a.host, a.port), handler_cls)
    print("[%s] listening on http://%s:%d/download?file=report.txt"
          % (handler_cls.tag, a.host, a.port), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
