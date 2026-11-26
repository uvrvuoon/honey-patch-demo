# 추가 검증 사례 — XFF 위조 / 같은 IP 동시 접속 / 공격 직후 정상 요청 (서버 ③)

- 실행 시각: 2026-11-26 16:39:41
- 실행 명령: `python tests/test_xff_cases.py`
- Python: 3.15.2 / OS: darwin
- 임시 미끼 data/decoy/public/report.txt: 없음

| 번호 | 단계 | file | XFF | 기대 (event / 기록 IP / 응답) | 실제 (event / 기록 IP / 응답) | 결과 |
|---|---|---|---|---|---|---|
| X1-1 | 공격자 공격 | `../secret/passwords.txt` | `'10.0.0.66'` | attack / 10.0.0.66 / fake | attack / '10.0.0.66' / fake | 일치 |
| X1-2 | 같은 공격자가 XFF를 10.0.0.77로 바꿔 정상 요청 | `report.txt` | `'10.0.0.77'` | sticky / 10.0.0.66 / public | - / - / public | **불일치** |
| X2-1 | 공격자 공격 | `../secret/passwords.txt` | `'10.0.0.66'` | attack / 10.0.0.66 / fake | attack / '10.0.0.66' / fake | 일치 |
| X2-2 | 같은 공격자가 헤더 없이 정상 요청 | `report.txt` | (없음) | sticky / 10.0.0.66 / public | - / - / public | **불일치** |
| X3-1 | 공격자가 XFF=10.0.0.10(정상 사용자 IP)으로 공격 | `../secret/passwords.txt` | `'10.0.0.10'` | attack / 10.0.0.10 / fake | attack / '10.0.0.10' / fake | 일치 |
| X3-2 | 진짜 정상 사용자(10.0.0.10) 정상 요청 | `report.txt` | `'10.0.0.10'` | - / - / public | sticky / '10.0.0.10' / public | **불일치** |
| X4-1 | XFF=',' 로 공격 | `../secret/passwords.txt` | `','` | attack / 127.0.0.1 / fake | attack / '127.0.0.1' / fake | 일치 |
| X5-1 | 공격자 공격 | `../secret/passwords.txt` | `'10.0.0.66'` | attack / 10.0.0.66 / fake | attack / '10.0.0.66' / fake | 일치 |
| X5-2 | 같은 공격자가 XFF=' 10.0.0.66 ' 로 정상 요청 | `report.txt` | `' 10.0.0.66 '` | sticky / 10.0.0.66 / public | sticky / '10.0.0.66' / public | 일치 |
| S1-1 | 공격자(10.0.0.50) 공격 | `../secret/passwords.txt` | `'10.0.0.50'` | attack / 10.0.0.50 / fake | attack / '10.0.0.50' / fake | 일치 |
| S1-2 | 같은 IP의 다른 정상 사용자 정상 요청 | `report.txt` | `'10.0.0.50'` | - / - / public | sticky / '10.0.0.50' / public | **불일치** |
| P1-1 | 공격자 공격 | `../secret/passwords.txt` | `'10.0.0.66'` | attack / 10.0.0.66 / fake | attack / '10.0.0.66' / fake | 일치 |
| P1-2 | 공격 직후 같은 IP 정상 요청 | `report.txt` | `'10.0.0.66'` | sticky / 10.0.0.66 / public | sticky / '10.0.0.66' / public | 일치 |
| P2-1 | 공격자 공격 | `../secret/passwords.txt` | `'10.0.0.66'` | attack / 10.0.0.66 / fake | attack / '10.0.0.66' / fake | 일치 |
| P2-2 | 공격 직후 같은 IP ..report.txt 요청 | `..report.txt` | `'10.0.0.66'` | sticky / 10.0.0.66 / public | sticky / '10.0.0.66' / public | 일치 |
| P3-1 | 공격자 공격 | `../secret/passwords.txt` | `'10.0.0.66'` | attack / 10.0.0.66 / fake | attack / '10.0.0.66' / fake | 일치 |
| P3-2 | 공격 직후 다른 IP(10.0.0.10) 정상 요청 | `report.txt` | `'10.0.0.10'` | - / - / public | - / - / public | 일치 |

| 번호 | 동시 접속 시험 | 라운드 | 정상 요청 sticky 기록 | 정상 요청이 가짜 응답 | 공격이 가짜가 아닌 응답 | 진짜 비밀 노출 |
|---|---|---|---|---|---|---|
| S2 | 같은 IP에서 공격·정상 요청 동시 전송 | 30 | 15 | 0 | 0 | 0 |
| S3 | 다른 IP에서 공격·정상 요청 동시 전송 | 30 | 0 | 0 | 0 | 0 |
