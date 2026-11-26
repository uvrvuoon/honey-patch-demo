# 수정된 버그 — 같은 입력으로 수정 전·후 재실행 (이수빈)

- 실행 시각: 2026-11-27 00:27:31
- 실행 명령: `python tests/before_after.py --with-fixed`
- Python: 3.14.3 / OS: win32
- 고정 사례 3종 (수정 후 코드): 결과: 9/9 통과 (고정 사례 3종 × 서버 3개)

## X4 — XFF 첫 값이 비어 있으면(',') 빈 문자열 ''을 IP로 기록 (발견: 안지민)

- 수정 내용: servers/honeypatch_server.py client_ip(): 첫 값이 비면 접속 주소 사용
- 수정 전: `17bd15e 14주차 실험 계획·가짜 파일 생성·측정 스크립트 추가 (윤아란)`
- 수정 후: 작업 폴더 (HEAD fd646a0, servers 수정 있음)
- 수정 전 버그 재현: **예** / 수정 후 명세대로: **예**

| 단계 | file | XFF | 기대 (명세) | 수정 전 | 수정 후 |
|---|---|---|---|---|---|
| XFF=',' 로 공격 | `../secret/passwords.txt` | `','` | status=200, verdict=fake, event=attack, ip='127.0.0.1' | status=200, verdict=fake, event=attack, ip='' ✗ | status=200, verdict=fake, event=attack, ip='127.0.0.1' |
| XFF=', 10.0.0.66' 로 공격 | `../secret/passwords.txt` | `', 10.0.0.66'` | status=200, verdict=fake, event=attack, ip='127.0.0.1' | status=200, verdict=fake, event=attack, ip='' ✗ | status=200, verdict=fake, event=attack, ip='127.0.0.1' |
| 같은 PC가 헤더 없이 report.txt (공격자로 기억됐는지) | `report.txt` | (없음) | status=200, verdict=public, event=sticky, ip='127.0.0.1' | status=200, verdict=public, event=-, ip=- ✗ | status=200, verdict=public, event=sticky, ip='127.0.0.1' |

## C1-② — 공개 폴더 이름의 대소문자만 바꾼 정상 요청을 public 밖으로 판정 (macOS) (발견: 이수빈 (코드 검토))

- 수정 내용: servers/patched_server.py check_path(): 문자열로 밖이면 상위 폴더가 public과 같은 폴더인지 samefile로 재확인
- **건너뜀**: 대소문자를 구분하지 않고 realpath가 대소문자를 맞추지 않는 환경(macOS)에서만 재현 (실행 OS: win32)

## C1-③ — 같은 요청을 서버 ③이 공격으로 기록하고 그 사용자를 sticky로 기억 (macOS) (발견: 이수빈 (코드 검토))

- 수정 내용: 위와 같음 (서버 ③은 서버 ②의 check_path()를 사용)
- **건너뜀**: 대소문자를 구분하지 않고 realpath가 대소문자를 맞추지 않는 환경(macOS)에서만 재현 (실행 OS: win32)
