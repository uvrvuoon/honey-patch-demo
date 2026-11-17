"""서버 ② — 일반 패치 버전.

요청 파일의 '실제 경로'(realpath: '..'·'.'·심볼릭 링크를 모두 해석한 결과)가
public 디렉터리 밖이면 403 오류를 반환한다.

판단 기준은 문자열에 '..'이 들어 있는지가 아니라 실제 경로다.
  - ..report.txt          -> public/..report.txt   (안쪽, 200)  # 경계 사례
  - ../public/report.txt  -> public/report.txt     (안쪽, 200)
  - ../secret/passwords.txt -> secret/passwords.txt (밖, 403)

실행: python servers/patched_server.py   (기본 포트 8002)
"""
import os

from common import PUBLIC_DIR, Blocked, DownloadHandler, run

PUBLIC_REAL = os.path.realpath(PUBLIC_DIR)


def check_path(name):
    """요청 이름 -> (허용 여부, 실제 경로). 서버 ③·테스트에서도 재사용 가능."""
    real = os.path.realpath(os.path.join(PUBLIC_REAL, name))
    # Windows는 대소문자를 구분하지 않으므로 normcase로 맞춘 뒤 비교
    base = os.path.normcase(PUBLIC_REAL)
    try:
        inside = os.path.commonpath([os.path.normcase(real), base]) == base
    except ValueError:  # Windows에서 드라이브가 다른 경우(C: vs D:)
        inside = False
    return inside, real


class PatchedHandler(DownloadHandler):
    tag = "server2-patched"

    def resolve(self, name):
        inside, real = check_path(name)
        if not inside:
            raise Blocked(real)
        return real


if __name__ == "__main__":
    run(PatchedHandler, 8002)
