# Honey Patch Demo — 경로 이탈(Path Traversal) 다운로드 서버

> README 초안 (저장소 생성 시 윤아란 작성). 설치·실행·원논문과의 차이 등 전체 내용은 **황은영**이 정리합니다.
> 각 서버 담당자는 자기 서버 절만 채워 주세요.

대상 논문: *From Patches to Honey Patches: Lightweight Attacker Misdirection, Deception, and Disinformation* (ACM CCS 2014)

| 모드 | 파일 | 포트 | 담당 |
|---|---|---|---|
| ① 무방비 | `servers/vulnerable_server.py` | 8001 | 윤아란 |
| ② 일반 패치 | `servers/patched_server.py` | 8002 | 윤아란 |
| ③ 허니패치 | `servers/honeypatch_server.py` | 8003 | 안지민 |

## 폴더 구조

```
honey-patch-demo/
├── servers/
│   ├── common.py              # ①②③ 공통 HTTP 처리 (각 서버는 resolve()만 구현)
│   ├── vulnerable_server.py   # ① 윤아란
│   ├── patched_server.py      # ② 윤아란
│   └── honeypatch_server.py   # ③ 안지민
├── data/
│   ├── public/      # report.txt, ..report.txt (경계 사례용)
│   ├── secret/      # passwords.txt (실제 비밀 — 실습용 가짜 값, SECRET_MARKER 포함)
│   └── decoy/       # 가짜 파일 (Faker 생성)
├── web/index.html   # 이수빈
├── tests/test_cases.py  # 김진하
├── logs/
├── requirements.txt
└── README.md        # 황은영
```

## 설치 및 실행

<!-- 황은영 작성 -->

```bash
pip install -r requirements.txt   # 서버 ①②는 표준 라이브러리만 사용 (설치 없이 실행 가능)
python servers/vulnerable_server.py      # ① → http://127.0.0.1:8001
python servers/patched_server.py         # ② → http://127.0.0.1:8002
python servers/honeypatch_server.py      # ③ → http://127.0.0.1:8003
```

## 서버 ①② (윤아란)

- **①**: `file` 값을 검증 없이 `data/public` 경로에 이어 붙임 → `../secret/passwords.txt` 요청 시 비밀 파일 유출
- **②**: `os.path.realpath()`로 `..`·심볼릭 링크를 해석한 **실제 경로**가 `data/public` 밖이면 403.
  `..` 포함 여부로 판단하지 않으므로 경계 사례 `..report.txt`는 200.
  판정 함수 `check_path(name) -> (허용 여부, 실제 경로)`는 ③에서 `from patched_server import check_path`로 재사용 가능.

| 상황 | 상태 코드 |
|---|---|
| 파일 반환 | 200 |
| 실제 경로가 `public` 밖 (②) | 403 |
| 파일 없음 / 디렉터리 | 404 |
| `file` 파라미터 누락, 널 바이트 포함 | 400 |

서버 내부 판정 로그(`SERVE` / `BLOCK` / `MISS`)는 공격자 응답과 구분해 stderr로만 출력.

| 입력 | 실제 경로 | ① | ② |
|---|---|---|---|
| `report.txt` (정상) | public/report.txt | 200 | 200 |
| `../secret/passwords.txt` (위반) | secret/passwords.txt | 200 (유출) | 403 |
| `..report.txt` (경계) | public/..report.txt | 200 | 200 |

①② 단독 동작 확인: `python tests/smoke_servers_1_2.py`
(공식 검증은 김진하의 `tests/test_cases.py`)

참고: Windows에서는 `\`도 경로 구분자라 `..\secret\passwords.txt`가 403, Linux/macOS에서는 `\`가 일반 문자라 404.

## 서버 ③ (안지민)

- **판정**: 서버 ②와 같은 `check_path()`로 실제 경로가 `data/public` 안인지 판단
- **public 안**: 실제 파일을 200으로 응답
- **public 밖(공격)**: 403 대신 `data/decoy/` 아래 **같은 상대 위치**의 가짜 파일을 200으로 응답
  (예: `data/secret/passwords.txt` → `data/decoy/secret/passwords.txt`). 가짜 파일이 없으면 404
- **공격자 기억(sticky)**: 한 번 공격한 IP는 기억해 두고, 이후 요청도 같은 위치에 가짜 파일이 있으면 그것을 응답
- **IP 판단**: `X-Forwarded-For` 헤더의 첫 값 우선, 없으면 실제 접속 주소
- **가짜 파일**: Faker로 생성(`seed 2026`), `SECRET_MARKER` 없음

| 입력 | ③ 응답 |
|---|---|
| `report.txt` (정상) | 200, 실제 파일 |
| `../secret/passwords.txt` (위반) | 200, 가짜 계정 목록 |
| `..report.txt` (경계) | 200, 실제 파일 |

공격 로그 `logs/honeypatch.log` (한 줄에 JSON 하나):

    {"time": "2026-11-19 18:42:37", "ip": "10.0.0.66", "path": "../secret/passwords.txt", "event": "attack"}
    {"time": "2026-11-19 18:42:44", "ip": "10.0.0.66", "path": "report.txt", "event": "sticky"}

- `attack`: public 밖 요청 감지 → 가짜 파일 응답
- `sticky`: 기억된 공격자 IP의 이후 요청

## 원논문과의 차이

<!-- 황은영: CRIU·LXC·TCP 이전 제외, 요청 단위 미끼 전환 등 -->

## 팀원 및 역할

| 이름 | 담당 |
|---|---|
| 윤아란 | 저장소, 서버 ①②, 실제·비밀 파일 샘플 |
| 안지민 | 서버 ③ 허니패치, 3종 서버 첫 실행 |
| 김진하 | 검증 사례 자동 실행, 전·후 비교 |
| 이수빈 | 비교 웹 화면, AI 사용 기록 취합, 보고서 |
| 황은영 | README, 재현 |
