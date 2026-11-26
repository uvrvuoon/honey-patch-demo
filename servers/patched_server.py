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
    if not inside:
        # macOS(기본 APFS)는 대소문자를 구분하지 않지만 normcase·realpath가 대소문자를
        # 맞춰 주지 않는다. 그래서 '../PUBLIC/report.txt'처럼 공개 폴더 이름의 대소문자만
        # 바꾼 정상 요청이 문자열로는 public 밖으로 보인다 (13주차 C1).
        # 실제 경로의 상위 폴더 중 public과 '물리적으로 같은 폴더'가 있으면 안쪽으로 본다.
        inside = _under_public(real)
    return inside, real


def _under_public(real):
    """real 또는 그 상위 폴더가 public과 같은 폴더(같은 장치·inode)인지"""
    p = real
    while True:
        try:
            if os.path.samefile(p, PUBLIC_REAL):
                return True
        except OSError:  # 없는 경로는 건너뛰고 상위로
            pass
        parent = os.path.dirname(p)
        if parent == p:
            return False
        p = parent


class PatchedHandler(DownloadHandler):
    tag = "server2-patched"

    def resolve(self, name):
        inside, real = check_path(name)
        if not inside:
            raise Blocked(real)
        return real


if __name__ == "__main__":
    run(PatchedHandler, 8002)
