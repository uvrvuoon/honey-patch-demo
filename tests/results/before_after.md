# 수정된 버그 — 같은 입력으로 수정 전·후 재실행 (이수빈)

- 실행 시각: 2026-11-26 19:41:11
- 실행 명령: `python tests/before_after.py --with-fixed`
- Python: 3.14.3 / OS: win32
- 고정 사례 3종 (수정 후 코드): 결과: 9/9 통과 (고정 사례 3종 × 서버 3개)

## X4 — XFF 첫 값이 비어 있으면(',') 빈 문자열 ''을 IP로 기록 (발견: 안지민)

- 수정 내용: servers/honeypatch_server.py client_ip(): 첫 값이 비면 접속 주소 사용
- 수정 전: `17bd15e 14주차 실험 계획·가짜 파일 생성·측정 스크립트 추가 (윤아란)`
- 수정 후: 작업 폴더 (HEAD 488743a)
- 수정 전 버그 재현: **예** / 수정 후 명세대로: **예**

| 단계 | file | XFF | 기대 (명세) | 수정 전 | 수정 후 |
|---|---|---|---|---|---|
| XFF=',' 로 공격 | `../secret/passwords.txt` | `','` | status=200, verdict=fake, event=attack, ip='127.0.0.1' | status=200, verdict=fake, event=attack, ip='' ✗ | status=200, verdict=fake, event=attack, ip='127.0.0.1' |
| XFF=', 10.0.0.66' 로 공격 | `../secret/passwords.txt` | `', 10.0.0.66'` | status=200, verdict=fake, event=attack, ip='127.0.0.1' | status=200, verdict=fake, event=attack, ip='' ✗ | status=200, verdict=fake, event=attack, ip='127.0.0.1' |
| 같은 PC가 헤더 없이 report.txt (공격자로 기억됐는지) | `report.txt` | (없음) | status=200, verdict=public, event=sticky, ip='127.0.0.1' | status=200, verdict=public, event=-, ip=- ✗ | status=200, verdict=public, event=sticky, ip='127.0.0.1' |
