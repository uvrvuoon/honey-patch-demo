# 추가 검증 사례 — 같은 공격 반복 / 미끼 없는 파일 공격 / 서버 ③ 재시작 (이수빈)

- 실행 시각: 2026-11-26 19:37:41
- 실행 명령: `python tests/test_repeat_restart_cases.py --repeat 20 --burst 30`
- Python: 3.14.3 / OS: win32
- 기대값은 실행 전에 작성 (README 6·8절 명세 기준), 결과에 맞춰 고치지 않음
- 서버 ③ 응답 속 진짜 비밀번호: **총 0개**

| 번호 | 서버 | 단계 | file | 기대 | 실제 | 결과 |
|---|---|---|---|---|---|---|
| R1-1 | ① | 같은 공격 20회 순서대로 | `../secret/passwords.txt` | status=200, verdict=leak, secret_hits=3, body_kinds=1 | status=200, verdict=leak, secret_hits=3, body_kinds=1 | 일치 |
| R1-2 | ② | 같은 공격 20회 순서대로 | `../secret/passwords.txt` | status=403, verdict=blocked, secret_hits=0, body_kinds=1 | status=403, verdict=blocked, secret_hits=0, body_kinds=1 | 일치 |
| R1-3 | ③ | 같은 공격 20회 순서대로 | `../secret/passwords.txt` | status=200, verdict=fake, secret_hits=0, body_kinds=1, attack_lines=20, other_lines=0 | status=200, verdict=fake, secret_hits=0, body_kinds=1, attack_lines=20, other_lines=0 | 일치 |
| R2-1 | ③ | 같은 공격 30건 동시 전송 | `../secret/passwords.txt` | fake=30, secret_hits=0, log_lines=30, broken_lines=0 | fake=30, secret_hits=0, log_lines=30, broken_lines=0 | 일치 |
| R3-1 | ③ | 공격 1회 | `../secret/passwords.txt` | verdict=fake, event=attack | verdict=fake, event=attack | 일치 |
| R3-2 | ③ | 같은 IP가 report.txt 20회 | `report.txt` | verdict=public, sticky_lines=20, secret_hits=0 | verdict=public, sticky_lines=20, secret_hits=0 | 일치 |
| M1-1 | ① | 소스 코드 파일 공격 | `../../servers/common.py` | status=200, same_as_real_file=True | status=200, same_as_real_file=True | 일치 |
| M1-2 | ② | 소스 코드 파일 공격 | `../../servers/common.py` | status=403 | status=403 | 일치 |
| M1-3 | ③ | 소스 코드 파일 공격 | `../../servers/common.py` | status=404, event=attack, log_ip=10.0.0.66, real_content_leaked=False, secret_hits=0 | status=404, event=attack, log_ip=10.0.0.66, real_content_leaked=False, secret_hits=0 | 일치 |
| M1-4 | ③ | 위 공격 직후 같은 IP가 report.txt | `report.txt` | verdict=public, event=sticky | verdict=public, event=sticky | 일치 |
| M2-1 | ① | OS 파일 공격 | `../../../../../../../../../../../../../../../Windows/win.ini` | status=200, same_as_real_file=True | status=200, same_as_real_file=True | 일치 |
| M2-2 | ② | OS 파일 공격 | `../../../../../../../../../../../../../../../Windows/win.ini` | status=403 | status=403 | 일치 |
| M2-3 | ③ | OS 파일 공격 | `../../../../../../../../../../../../../../../Windows/win.ini` | status=404, event=attack, log_ip=10.0.0.66, real_content_leaked=False, secret_hits=0 | status=404, event=attack, log_ip=10.0.0.66, real_content_leaked=False, secret_hits=0 | 일치 |
| M2-4 | ③ | 위 공격 직후 같은 IP가 report.txt | `report.txt` | verdict=public, event=sticky | verdict=public, event=sticky | 일치 |
| M3-1 | ① | 없는 파일 공격 | `../secret/none.txt` | status=404, same_as_real_file=False | status=404, same_as_real_file=False | 일치 |
| M3-2 | ② | 없는 파일 공격 | `../secret/none.txt` | status=403 | status=403 | 일치 |
| M3-3 | ③ | 없는 파일 공격 | `../secret/none.txt` | status=404, event=attack, log_ip=10.0.0.66, real_content_leaked=False, secret_hits=0 | status=404, event=attack, log_ip=10.0.0.66, real_content_leaked=False, secret_hits=0 | 일치 |
| M3-4 | ③ | 위 공격 직후 같은 IP가 report.txt | `report.txt` | verdict=public, event=sticky | verdict=public, event=sticky | 일치 |
| RS-1 | ③ | 재시작 전: 공격 | `../secret/passwords.txt` | verdict=fake, event=attack | verdict=fake, event=attack | 일치 |
| RS-2 | ③ | 재시작 전: 같은 IP report.txt | `report.txt` | verdict=public, event=sticky | verdict=public, event=sticky | 일치 |
| RS-3 | ③ | 재시작 직후: 로그 파일 | `-` | log_lines_kept=True | log_lines_kept=True | 일치 |
| RS-4 | ③ | 재시작 후: 같은 IP report.txt | `report.txt` | verdict=public, event=- | verdict=public, event=- | 일치 |
| RS-5 | ③ | 재시작 후: 같은 IP 다시 공격 | `../secret/passwords.txt` | verdict=fake, event=attack, secret_hits=0 | verdict=fake, event=attack, secret_hits=0 | 일치 |
| RS-6 | ③ | 재시작 후 재공격 뒤: 같은 IP report.txt | `report.txt` | verdict=public, event=sticky | verdict=public, event=sticky | 일치 |

## 참고 (명세와 허니패치 목표의 차이)

- M1-3: 명세상 404가 맞지만, 무방비 서버(①)라면 200이 나왔을 파일이라 공격자가 ③을 '무방비 서버가 아님'으로 구분할 수 있음
- M2-3: 명세상 404가 맞지만, 무방비 서버(①)라면 200이 나왔을 파일이라 공격자가 ③을 '무방비 서버가 아님'으로 구분할 수 있음
- RS-4: 공격자 기억이 메모리에만 있어 재시작하면 sticky가 풀림 (README 8절)
