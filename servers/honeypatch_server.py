"""서버 ③ — 허니패치 버전.

판정은 서버 ②와 같은 check_path()를 쓴다.
  - public 안: 실제 파일을 200으로 응답
  - public 밖: 403 대신 data/decoy/ 아래 같은 위치의 가짜 파일을 응답하고,
    공격 정보를 logs/honeypatch.log에 JSON 한 줄로 기록한다.
  - 한 번 공격한 IP(X-Forwarded-For 기준)는 기억해 두고, 이후 요청도 미끼 쪽으로 보낸다.

실행: python servers/honeypatch_server.py   (기본 포트 8003)
"""
import json
import os
import threading
import time

from common import DATA_DIR, REPO_ROOT, DownloadHandler, run
from patched_server import check_path

DATA_REAL = os.path.realpath(DATA_DIR)
DECOY_DIR = os.path.join(DATA_REAL, "decoy")
DECOY_LOG = os.path.join(REPO_ROOT, "logs", "honeypatch.log")
_lock = threading.Lock()
_attackers = set()


def decoy_path(real):
    """실제 경로(data 기준 상대 위치)를 decoy 디렉터리의 같은 위치로 바꾼다."""
    try:
        rel = os.path.relpath(real, DATA_REAL)
    except ValueError:
        rel = None
    if rel is None or rel.startswith(".."):
        rel = os.path.join("outside", os.path.basename(real))
    return os.path.join(DECOY_DIR, rel)


class HoneypatchHandler(DownloadHandler):
    tag = "server3-honeypatch"

    def client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def resolve(self, name):
        ip = self.client_ip()
        inside, real = check_path(name)
        if not inside:
            with _lock:
                _attackers.add(ip)
            self._event(ip, name, "attack")
            return decoy_path(real)
        with _lock:
            known = ip in _attackers
        if known:
            decoy = decoy_path(real)
            self._event(ip, name, "sticky")
            return decoy if os.path.isfile(decoy) else real
        return real

    def _event(self, ip, name, event):
        entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "ip": ip, "path": name, "event": event}
        with _lock, open(DECOY_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        self._defense_log(event.upper(), name, ip)


if __name__ == "__main__":
    run(HoneypatchHandler, 8003)