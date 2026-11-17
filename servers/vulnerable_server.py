"""서버 ① — 미패치(취약) 버전.

/download?file=<이름> 요청을 경로 검증 없이 처리한다.
사용자 입력을 public 디렉터리 경로에 그대로 이어 붙이므로
file=../secret/passwords.txt 같은 경로 이탈(Path Traversal)이 그대로 성공한다.

실행: python servers/vulnerable_server.py   (기본 포트 8001)
"""
import os

from common import PUBLIC_DIR, DownloadHandler, run


class VulnHandler(DownloadHandler):
    tag = "server1-vuln"

    def resolve(self, name):
        # [취약점] 검증 없음: '..', 절대 경로, 심볼릭 링크 모두 통과
        return os.path.join(PUBLIC_DIR, name)


if __name__ == "__main__":
    run(VulnHandler, 8001)
