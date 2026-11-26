# Honey-Patch — 경로 이탈(Path Traversal) 다운로드 서버 3종 비교

같은 해킹 시도를 서버 3개에 동시에 보내고, 각 서버의 반응을 웹 화면 하나에서 나란히 비교하는 데모입니다.

- 대상 논문: *From Patches to Honey-Patches: Lightweight Attacker Misdirection, Deception, and Disinformation* (ACM CCS 2014)
- 공격: 다운로드 주소의 `file=` 값을 `../secret/passwords.txt`로 바꿔 비밀 폴더의 파일을 받아 가는 경로 이탈 공격

| 모드 | 공격(`../secret/passwords.txt`) 시 응답 | 파일 | 포트 | 담당 |
|---|---|---|---|---|
| ① 무방비 | **진짜 비밀번호 파일 유출** | `servers/vulnerable_server.py` | 8001 | 윤아란 |
| ② 일반 패치 | 403 오류 (공격자가 "막혔다"는 걸 알게 됨) | `servers/patched_server.py` | 8002 | 윤아란 |
| ③ 허니패치 | 200 성공처럼 보이지만 **내용은 전부 가짜**, 공격자 기억·기록 | `servers/honeypatch_server.py` | 8003 | 안지민 |
| 비교 화면 | 세 서버에 같은 요청을 보내고 결과를 나란히 표시 | `web/app.py`, `web/index.html` | 8000 | 이수빈 |

---

## 1. 실행 환경

| 항목 | 내용 |
|---|---|
| Python | 3.7 이상 |
| 추가 패키지 | 필요 없음 (서버 ①②③, 비교 화면, 검증 스크립트 모두 Python 표준 라이브러리만 사용) |
| OS | Windows 11·macOS에서 실행 확인 (Linux는 일부만 확인). 일부 입력은 OS에 따라 결과가 다릅니다 — 6절 맨 아래 참고 |
| 브라우저 | 아무 브라우저 (Chrome, Edge, Safari 등) |


### Python 명령어 이름 (OS마다 다름)

| OS | 명령어 | 확인 방법 |
|---|---|---|
| macOS / Linux | `python3` | `python3 --version` |
| Windows | `py` 또는 `python` | `py --version` |

---

## 2. 빠른 실행 (터미널 4개)

### 2-1. 저장소 받기

```bash
git clone <저장소 주소>
cd honey-patch-demo
```

- 이후 모든 명령은 저장소 맨 위 폴더(`honey-patch-demo`)에서 실행합니다.
- 코드가 저장소 기준 상대 경로를 쓰므로 어느 PC에 받아도 경로를 고칠 필요가 없습니다.

### 2-2. 서버 4개 켜기

터미널 창 4개를 열고, 각 창에서 `honey-patch-demo` 폴더로 이동한 뒤 한 줄씩 실행합니다.

| 창 | 명령어 | 정상 실행 시 출력 |
|---|---|---|
| 1 | `python3 servers/vulnerable_server.py` | `[server1-vuln] listening on http://127.0.0.1:8001/...` |
| 2 | `python3 servers/patched_server.py` | `[server2-patched] listening on http://127.0.0.1:8002/...` |
| 3 | `python3 servers/honeypatch_server.py` | `[server3-honeypatch] listening on http://127.0.0.1:8003/...` |
| 4 | `python3 web/app.py` | `[web] 비교 화면: http://127.0.0.1:8000` |

### 2-3. 브라우저로 열기

http://127.0.0.1:8000 에 접속합니다.

- 화면 위쪽 ①②③ 켜짐 표시가 모두 초록색이면 준비가 끝난 것입니다.
- `꺼짐`이 있으면 해당 서버 창의 오류 메시지를 확인합니다.

### 2-4. 끄기

각 창에서 `Ctrl + C`.

---

## 3. 검증 사례와 실험 실행

같은 입력을 서버 ①②③에 똑같이 보내 보호 적용 전(①) → 일반 패치(②) → 허니패치(③) 의 결과를 비교하는 것이 목적입니다.

3-1 ~ 3-5는 11주차에 정한 **고정 사례 3종**, 3-6은 13주차에 더한 **추가 사례**, 3-7은 14주차 **실험**입니다.

| 사례 | 입력 | 확인하는 것 | 이 입력을 고른 이유 |
|---|---|---|---|
| 정상 | `file=report.txt` | 보호를 적용해도 정상 사용자가 그대로 파일을 받는지 (②③에서 불필요한 차단·미끼 이동이 없는지) | `data/public` 안의 평범한 파일입니다. 세 서버 모두 같은 결과가 나와야 하는 기준선입니다. |
| 위반 | `file=../secret/passwords.txt` | ①에서 생기는 피해(진짜 비밀 유출)가 ②에서는 차단되고, ③에서는 가짜 파일로 바뀌는지 (③ 응답 속 진짜 비밀번호 0개) | `../`로 상위 폴더로 빠져나가는 가장 기본적인 경로 이탈 공격입니다. 원논문 실험의 Apache 주소 검사 취약점(CVE-2011-3368)과 성격이 비슷합니다. |
| 경계 | `file=..report.txt` | 이름에 `..`이 들어 있어도 실제로는 `public` 안의 파일이면 정상으로 판정하는지 (정상 사용자를 공격자로 오해하지 않는지) | 문자열에 `..`이 있는지만 보는 허술한 검사라면 공격으로 잘못 판정되는 입력입니다. ②③이 실제 경로 기준으로 판단하는지 확인합니다. |

- 정상·경계 사례에서는 ①②③ 모두 같은 공개 파일을 돌려줘야 하고, ③의 미끼 이동이 없어야 합니다. → 오탐 확인
- 위반 사례에서는 ① 유출(보호 전 피해 재현), ② 403(막지만 공격자가 눈치챔), ③ 가짜 파일(막으면서 공격자를 속임)로 갈려야 합니다. → 허니패치 효과 확인

### 3-1. 비교 화면에서 실행

버튼을 누르면 세 서버에 같은 요청이 동시에 전송됩니다.

| 버튼 | 보내는 값 | 보내는 사람 |
|---|---|---|
| 정상 요청 | `report.txt` | 정상 사용자 (10.0.0.10) |
| 공격 요청 | `../secret/passwords.txt` | 공격자 (10.0.0.66) |
| 경계 사례 | `..report.txt` (이름에 점 두 개가 있지만 폴더 이동은 아님) | 정상 사용자 (10.0.0.10) |

입력칸에 다른 파일 이름을 넣고 `정상 사용자` / `공격자`를 고른 뒤 세 서버에 보내기로도 실행 가능합니다.

### 3-2. 기대 결과

| 사례 | ① 무방비 | ② 일반 패치 | ③ 허니패치 |
|---|---|---|---|
| 정상 `report.txt` | 200, 공개 파일 | 200, 공개 파일 | 200, 공개 파일 · 미끼 이동 아니요 |
| 위반 `../secret/passwords.txt` | 200, 진짜 비밀 유출 (진짜 비밀번호 3개) | 403, 차단 | 200, 가짜 파일 · 진짜 비밀번호 0개 · 미끼 이동 예 |
| 경계 `..report.txt` | 200, 공개 파일 | 200, 공개 파일 | 200, 공개 파일 · 미끼 이동 아니요 |

판정 기준 (화면이 자동 판정):

- 진짜 비밀 유출: 응답 본문이 `data/secret/` 파일 내용과 같거나, 진짜 비밀번호 줄을 하나라도 포함
- 가짜 파일(미끼): 응답 본문이 `data/decoy/` 파일 내용과 같음
- 미끼 이동 예: 서버 ③이 가짜 파일로 응답했거나, 요청 중 `logs/honeypatch.log`에 새 줄이 생김
- 오탐 없음: 정상·경계 사례에서 ③의 미끼 이동이 `아니요`

### 3-3. 화면 없이 명령어로 확인

서버 ①②③만 켠 상태에서 실행. Windows PowerShell에서는 `curl` 대신 `curl.exe` 사용.

```bash
# 위반 사례: ①은 진짜 비밀번호, ②는 403, ③은 가짜 비밀번호
curl -i "http://127.0.0.1:8001/download?file=../secret/passwords.txt"
curl -i "http://127.0.0.1:8002/download?file=../secret/passwords.txt"
curl -i -H "X-Forwarded-For: 10.0.0.66" "http://127.0.0.1:8003/download?file=../secret/passwords.txt"

# 정상 사례 / 경계 사례 (포트만 바꿔 ①②③ 각각 확인)
curl -i "http://127.0.0.1:8003/download?file=report.txt"
curl -i "http://127.0.0.1:8003/download?file=..report.txt"
```

### 3-4. 서버 ①② 자동 테스트

```bash
python3 tests/smoke_servers_1_2.py
```

- 마지막 줄이 `결과: 8/8 통과`면 정상 (실패 시 종료 코드 1)

### 3-5. 고정 사례 3종 자동 실행 (서버 ①②③ 비교)

```bash
python3 tests/test_cases.py
```

- 서버를 미리 켜 두지 않아도 됩니다. 스크립트가 ①②③을 빈 포트로 직접 띄우고, 끝나면 내립니다.
- 고정 사례 3종을 같은 입력으로 세 서버에 보내고, 응답 코드·응답 내용(진짜/가짜)·미끼 전환 여부·응답 시간을 표로 출력한 뒤 11주차 기대 결과표(3-2)와 대조해 PASS/FAIL을 냅니다.
- 마지막 줄이 `결과: 9/9 통과`면 정상 (실패 시 종료 코드 1, 어긋난 항목의 기대값·실제값을 함께 출력)
- 실행 결과는 `tests/results/results.md`(보고서에 붙여 넣을 표)와 `tests/results/results.json`에 저장됩니다.

| 옵션 | 뜻 |
|---|---|
| `--use-running` | 서버를 띄우지 않고 이미 켜 둔 8001/8002/8003에 요청 (`--s1`, `--s2`, `--s3`로 포트 변경) |
| `--repeat N` | 위반 사례를 N회 반복해 ①②③의 응답 시간·응답 종류 비교 |
| `--no-save` | 결과 파일(`tests/results/`)을 쓰지 않음 |

- 기대값은 코드 안 `CASES`에 고정해 두었습니다. 결과가 다르면 기대값이 아니라 구현이나 원인을 확인합니다 (11주차 고정 규칙).
- `--use-running`으로 돌릴 때는 서버 ③을 다시 켜고 실행하세요. 앞선 시연에서 기억된 공격자 IP가 남아 있으면 정상·경계 사례가 미끼로 갈 수 있습니다 (4절 초기화).

### 3-6. 13주차 추가 검증 사례

고정 사례 3종(3-5)은 그대로 두고, 더 다양한 입력으로 시험한 스크립트입니다. 모두 서버를 미리 켤 필요가 없습니다. 실행 중 생긴 `logs/honeypatch.log`는 실행 전 상태로 되돌리고, `before_after.py`는 임시 폴더에서 돌려 저장소의 로그·코드를 아예 건드리지 않습니다.

| 스크립트 | 무엇을 시험하나 | 결과 파일 |
|---|---|---|
| `python3 tests/test_xff_cases.py`<br>(안지민) | `X-Forwarded-For` 위조, 같은 IP 동시 접속, 공격 직후 정상 요청 | `tests/results/xff_results*.md` |
| `python3 tests/test_repeat_restart_cases.py`<br>(이수빈) | 같은 공격 반복, 미끼 없는 파일 공격, 서버 ③ 재시작 전·후 | `tests/results/repeat_restart_results.md` |
| `python3 tests/test_encoding_cases.py`<br>(김진하) | 같은 공격을 다른 표기로: 경로 구분자 `..\`, URL 인코딩(1회·2중·대문자), 대소문자, 절대 경로, 빈 값, 널 바이트, 경로 중간 `..` | `tests/results/encoding_results.md` |
| `python3 tests/timing_1_vs_3.py`<br>(이수빈) | 같은 공격에 대한 ①과 ③의 응답 시간 차 | `tests/results/timing_1_vs_3.md` |
| `python3 tests/before_after.py`<br>(이수빈) | 고친 버그를 같은 입력으로 수정 전·후 재실행 | `tests/results/before_after.md` |

추가 옵션:

| 명령 | 뜻 |
|---|---|
| `python3 tests/test_xff_cases.py --public-decoy` | 임시 가짜 `report.txt`를 두고 실행해, 오탐이 응답 내용까지 바꾸는지 확인 |
| `python3 tests/test_encoding_cases.py --fresh` | 사례마다 서버 ③을 새로 띄워 앞 사례의 영향(공격자 IP 기억)을 없앰 |
| `python3 tests/test_encoding_cases.py --fresh --label macos` | 결과 파일 이름 뒤에 말을 붙여 저장 (다른 OS 결과가 서로 덮어쓰지 않게) |
| `python3 tests/before_after.py --with-fixed` | 끝에 고정 사례 3종도 다시 실행 |

- `test_encoding_cases.py`는 실행 환경을 먼저 확인해(`\`가 경로 구분자인지, 파일 시스템이 대소문자를 구분하는지) 그 환경에 맞는 기대값 표를 씁니다. 같은 입력이 Windows와 macOS/Linux에서 다르게 판정되기 때문입니다 (6절 맨 아래).
- 추가 사례의 기대값·결과·반례 분류는 `docs/13w_encoding_cases_jinha.md`와 각 결과 파일에 있습니다.

### 3-7. 14주차 실험 (가짜 파일 수에 따른 응답 시간)

```bash
python3 tests/bench.py                      # 10/100/1000개 × 200회 × 3라운드
python3 tests/make_decoys.py --count 100    # 가짜 파일만 따로 만들기 (--clean / --status)
```

- 계획(변수·지표·반복 횟수·측정 조건): `docs/experiment_plan.md`
- 결과: `tests/results/bench.md`(표), `tests/results/bench.json`(원자료)
- 끝나면 생성한 가짜 파일을 지우고 로그를 실행 전 상태로 되돌립니다.

---

## 4. 로그 확인과 초기화

공격자가 받는 응답과 방어자(서버) 내부 판정 기록을 분리.

| 기록 | 위치 | 내용 |
|---|---|---|
| 서버 판정 로그 | 각 서버를 켠 터미널 창 (stderr) | `SERVE`(파일 응답), `BLOCK`(403 차단), `MISS`(404), `ATTACK`, `STICKY` |
| 공격 기록 (미끼 방 감시 기록) | `logs/honeypatch.log` (서버 ③ 실행 시 생성) | JSON 한 줄에 요청 하나. 비교 화면 오른쪽 미끼 방 감시 기록에 실시간 표시 |

`logs/honeypatch.log` 예시:

```
{"time": "2026-11-21 01:04:58", "ip": "10.0.0.66", "path": "../secret/passwords.txt", "event": "attack"}
{"time": "2026-11-21 01:04:58", "ip": "10.0.0.66", "path": "report.txt", "event": "sticky"}
```

- `attack`: `public` 밖 파일 요청 감지 → 가짜 파일로 응답
- `sticky`: 이미 공격한 IP의 재요청 (정상 파일 요청도 기록됨)

### 시연 전 초기화

서버 ③은 공격자 IP를 메모리에 기억하고, 로그 파일은 계속 쌓임. 처음 상태로 돌리려면:

1. 서버 ③ 창에서 `Ctrl + C` → 공격자 기억 초기화
2. 로그 파일 삭제
   - macOS / Linux: `rm logs/honeypatch.log`
   - Windows: `del logs\honeypatch.log`
3. 서버 ③ 다시 실행: `python3 servers/honeypatch_server.py`
4. 비교 화면에서 요청 기록 → 지우기 후 새로고침

`logs/honeypatch.log`는 실행할 때마다 각자 PC에 생기는 기록이라 Git에 올라가지 않도록 설정되어 있습니다.

---

## 5. 폴더 구조

```
honey-patch-demo/
├── servers/
│   ├── common.py              # ①②③ 공통 HTTP 처리 (각 서버는 resolve()만 구현)
│   ├── vulnerable_server.py   # ① 윤아란
│   ├── patched_server.py      # ② 윤아란 (판정 함수 check_path())
│   └── honeypatch_server.py   # ③ 안지민
├── web/
│   ├── app.py                 # 이수빈 — 비교 서버 (①②③에 대신 요청하고 결과 판정)
│   └── index.html             # 이수빈 — 3칸 비교 화면, 미끼 방 감시 기록, 요청 기록 표
├── data/
│   ├── public/                # report.txt, ..report.txt (경계 사례용)
│   ├── secret/                # passwords.txt (실제 비밀 — 실습용 가짜 값, SECRET_MARKER 포함)
│   └── decoy/
│       └── secret/
│           └── passwords.txt  # 가짜 비밀 (Faker 생성, seed 2026)
├── tests/
│   ├── smoke_servers_1_2.py          # 윤아란 — 서버 ①② 자동 테스트
│   ├── test_cases.py                 # 김진하 — 고정 사례 3종(11주차)을 ①②③에 보내고 기대 결과와 대조
│   ├── test_xff_cases.py             # 안지민 — XFF 위조·같은 IP·공격 직후 (13주차 추가)
│   ├── test_repeat_restart_cases.py  # 이수빈 — 반복 공격·미끼 없는 파일·재시작 (13주차 추가)
│   ├── test_encoding_cases.py        # 김진하 — 표기 변형 입력 (13주차 추가)
│   ├── timing_1_vs_3.py              # 이수빈 — ①③ 응답 시간 비교
│   ├── before_after.py               # 이수빈 — 고친 버그의 수정 전·후 재실행
│   ├── bench.py                      # 윤아란 — 가짜 파일 수에 따른 응답 시간 측정 (14주차 실험)
│   ├── make_decoys.py                # 윤아란 — 가짜 파일 대량 생성·삭제
│   └── results/                      # 위 스크립트들의 실행 결과 (.md 표 + .json 원자료)
├── docs/
│   ├── ai_usage_log.md               # AI 사용 기록 (취합: 이수빈)
│   ├── experiment_plan.md            # 윤아란 — 14주차 실험 계획
│   └── 13w_encoding_cases_jinha.md   # 김진하 — 13주차 추가 사례·반례 분류 정리
├── logs/                      # 서버 ③ 실행 시 honeypatch.log 생성
├── requirements.txt
└── README.md                  # 황은영
```

---

## 6. 서버별 동작

### 서버 ① 무방비

- `file` 값을 검증 없이 `data/public` 경로 뒤에 이어 붙임
- `../secret/passwords.txt` 요청 시 `data/secret/passwords.txt`가 그대로 응답됨

### 서버 ② 일반 패치

- `os.path.realpath()`로 `..`·심볼릭 링크를 해석한 실제 경로가 `data/public` 밖이면 403
- `..` 포함 여부가 아니라 실제 경로로 판단 → 경계 사례 `..report.txt`는 200
- 판정 함수 `check_path(name) -> (허용 여부, 실제 경로)`는 서버 ③에서도 재사용

### 서버 ③ 허니패치

- 판정: 서버 ②와 같은 `check_path()` 사용 → ②③의 판정 기준 동일
- public 안: 실제 파일을 200으로 응답
- public 밖(공격): 403 대신 `data/decoy/` 아래 같은 상대 위치의 가짜 파일을 200으로 응답
  (예: `data/secret/passwords.txt` → `data/decoy/secret/passwords.txt`). 가짜 파일이 없으면 404
- 공격자 기억(sticky): 한 번 공격한 IP를 기억, 이후 요청도 같은 위치에 가짜 파일이 있으면 가짜로 응답 (없으면 실제 파일)
- IP 판단: `X-Forwarded-For` 헤더의 첫 값 우선, 헤더가 없거나 **첫 값이 비어 있으면** 실제 접속 주소
  - 비교 화면은 모든 요청을 같은 PC에서 보내므로, 이 헤더로 정상 사용자(10.0.0.10)와 공격자(10.0.0.66)를 구분
  - 첫 값이 빈 경우(`X-Forwarded-For: ,`)에 빈 문자열을 IP로 쓰던 버그는 13주차에 수정했습니다 (반례 X4, `tests/results/before_after.md`)

### 상태 코드

| 상황 | 상태 코드 |
|---|---|
| 파일 응답 (③의 가짜 파일 포함) | 200 |
| 실제 경로가 `public` 밖 (②만) | 403 |
| 파일 없음 / 디렉터리 | 404 |
| `file` 값 누락, 널 바이트 포함 | 400 |

### OS에 따라 결과가 달라지는 입력

경로를 해석하는 규칙이 OS마다 달라서, **같은 입력이 OS에 따라 다르게 판정됩니다.** 13주차 추가 사례(`tests/test_encoding_cases.py`)는 이 두 속성을 실행 시작 때 확인해 해당 환경의 기대값을 씁니다.

| 입력 | Windows 11 (확인함) | Linux (확인함) | macOS (예상) |
|---|---|---|---|
| `..\secret\passwords.txt` | `\`가 경로 구분자 → ① 유출 / ② 403 / ③ 가짜 | `\`가 보통 글자 → **셋 다 404** | Linux와 같을 것 |
| `../SECRET/PASSWORDS.TXT` | 대소문자 구분 안 함 → ① 유출 / ② 403 / ③ 가짜 | 구분함 → ① 404 / **② 403 / ③ 404** | Windows와 같을 것 (기본 APFS는 구분 안 함) |

- 확인 결과: `tests/results/encoding_results_fresh.md`(Windows 11, Python 3.14), `tests/results/encoding_results_fresh_linux.md`(WSL Ubuntu 22.04, Python 3.10)
- 두 환경 모두 **기대와 30/30 일치**합니다. 스크립트가 환경 속성을 먼저 확인해 그 환경의 기대값을 쓰기 때문입니다.
- 어느 OS에서도 진짜 비밀이 ②③으로 새지는 않지만, **응답 코드가 달라져 재현 결과가 환경마다 다르게 보입니다.** OS별 경로 규칙 차이를 다루지 않기로 한 범위(명세상 미지원)로 기록합니다.
- Linux의 `../SECRET/PASSWORDS.TXT`에서는 ②가 403, ③이 404로 **갈립니다.** 대문자 이름에 맞는 가짜 파일이 미끼 폴더에 없기 때문이며, 8절의 "미끼 파일이 없는 경로"와 같은 문제입니다.

---

## 7. 자주 막히는 곳

| 증상 | 원인 / 해결 |
|---|---|
| `command not found: python` | macOS/Linux는 `python3`, Windows는 `py` 사용 |
| `Address already in use` / `WinError 10048` | 포트 사용 중. 이미 켜 둔 서버가 없는지 확인하거나 포트 변경: `python3 servers/patched_server.py --port 9002` → 비교 화면도 `python3 web/app.py --s2 9002` (`--port`, `--s1`, `--s2`, `--s3` 사용 가능) |
| 화면에 `꺼짐`, `서버 꺼짐` | 해당 서버 창이 꺼졌거나 오류로 종료됨. 창의 오류 메시지 확인 |
| 공격 후 정상 요청인데 `sticky` 기록됨 | 같은 IP로 보낸 경우. 화면에서 `정상 사용자`를 고르면 다른 IP로 전송됨. 처음 상태로 돌리려면 4절 초기화 |
| PowerShell에서 `curl` 결과가 이상함 | PowerShell의 `curl`은 다른 명령. `curl.exe` 사용 |

---

## 8. 원논문과의 차이

| 항목 | 원논문 | 이 구현 | 영향 |
|---|---|---|---|
| 대상 서버 | 실제 Apache 웹 서버 (C) | Python 표준 라이브러리 HTTP 서버 | 개념 시연용 축소 구현 |
| 취약점 | Apache CVE-2011-3368 등 실제 취약점 | 경로 이탈(`../`) 다운로드 취약점 | 같은 "입력 검사 누락" 성격 |
| 미끼 전환 방법 | 공격 순간 실행 중인 프로세스를 통째로 복제(CRIU)해 미끼 컨테이너(LXC)로 옮기고, 연결(TCP)도 이어 붙임 | 요청 하나마다 응답할 파일만 가짜 폴더(`data/decoy/`)로 교체 | 파일 읽기 공격만 속일 수 있음. 다른 종류의 공격은 격리 불가 |
| 비밀 보호 | 미끼 컨테이너의 메모리 속 비밀 데이터까지 가짜로 교체 | 미리 만든 가짜 파일로만 대체 | 메모리 속 비밀은 다루지 않음 |
| 공격자 구분 | 공격이 일어난 연결(세션) 단위 | IP 단위 (`X-Forwarded-For` 헤더) | 헤더 위조 가능 → 실제 환경에서는 신뢰 불가 |
| 공격자 기억 | 미끼 컨테이너 안에서 계속 동작 | 서버 ③ 메모리에 IP 목록 저장 | 서버 재시작 시 초기화 |
| 공격 시 응답 지연 | 메모리 치환·프로세스 복제 때문에 약 **0.25초** 느려짐 (논문 6.2절). 논문도 이를 탐지 단서로 인정 (7절) | 공격 요청이 ①보다 약 **1.6ms** 느림 (`tests/results/timing_1_vs_3.md`, 200회×3라운드 중앙값 차, 3라운드 모두 같은 방향). 원인은 미끼 전환 자체가 아니라 **요청마다 공격 로그를 파일에 한 줄 쓰는 비용**으로 보임 — 같은 서버 ③ 안에서도 로그를 쓰는 요청이 쓰지 않는 요청보다 모든 라운드에서 느림 (`tests/results/bench.md`) | 지연의 크기도 원인도 다름. 네트워크 지연에 묻힐 정도라 원격 공격자가 알아채기는 어려움 |
| 미끼 파일이 없는 경로 | 프로세스를 통째로 복제하므로 "미끼가 없는 파일"이라는 상황 자체가 없음 | 대응 가짜 파일이 없으면 404 → 같은 요청에 ①은 200을 주므로 **응답이 갈림** (`tests/results/repeat_restart_results.md` M1) | 미끼 폴더에 없는 파일을 노리면 허니패치임을 눈치챌 수 있음 |

---

## 9. 진행 상황과 남은 작업

| 항목 | 상태 |
|---|---|
| 서버 ①②③, 비교 화면 | 완료, 고정 사례 3종 기대 결과와 일치 |
| 서버 ①② 자동 테스트 | 완료 (`tests/smoke_servers_1_2.py`, 8/8) |
| 서버 ③ 포함 고정 사례 자동 실행 | 완료 (김진하, `tests/test_cases.py`, 9/9 통과) |
| 13주차 추가 검증 사례 | 완료 — XFF·동시 접속·상태 전이(안지민), 반복·미끼 없는 파일·재시작(이수빈), 표기 변형(김진하). 결과는 `tests/results/` |
| 반례와 수정 | X4(빈 XFF 첫 값 → 빈 IP 기록)만 구현 버그로 수정 완료. 나머지는 명세상 미지원·원논문 한계로 기록 (`tests/results/before_after.md`) |
| 실험 1: ①과 ③에 같은 공격, 응답 모양·시간 비교 | 완료 (이수빈, `tests/timing_1_vs_3.py`, 200회×3라운드). **3라운드 모두 ③이 느림**, 중앙값 차 1.591ms. 원인은 미끼 전환이 아니라 공격 로그 쓰기로 보임 (같은 서버 ③에서도 로그를 쓰는 요청이 모든 라운드에서 더 느림, `tests/results/bench.md`) |
| 실험 2: 가짜 파일 수(10/100/1000개)에 따른 응답 시간 | 계획·스크립트·예비 측정 완료 (윤아란, `docs/experiment_plan.md`, `tests/bench.py`). 예비 결과는 조건 간 차이가 라운드 간 흔들림보다 작아 "차이 없음". **본 측정은 14주차에 최신 커밋으로 다시 실행** |
| Windows 재현 확인 | 예정 (팀원 PC에서 README 안내대로 재실행) |

---

## 10. 팀원 및 역할

| 이름 | 담당 |
|---|---|
| 윤아란 | 저장소, 서버 ①②, 실제·비밀 파일 샘플 |
| 안지민 | 서버 ③ 허니패치, 3종 서버 첫 실행 |
| 김진하 | 검증 사례 자동 실행, 전·후 비교, 실험 측정 |
| 이수빈 | 비교 웹 화면, AI 사용 기록 취합, 주간 보고서 |
| 황은영 | README, 원논문과의 차이 정리, 재현 확인, 주간 보고서 |
