# claude-infra-audit-by-xum

KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 (2026)」 기준으로
Unix 서버 점검 raw data 를 받아 보안 취약점을 자동 진단하고, 결과 보고서(xlsx)를 만드는 도구.

판단은 **Claude Code (LLM)** 가 수행하고, 그 결과를 코드가 정해진 양식의 보고서로 정리한다.
일부 항목 (NFS, 메일 서비스) 은 LLM 판단을 그대로 신뢰하지 않고 룰 기반 코드가 재판정한다.

---

## 무엇을 점검하나

- **대상**: Unix 계열 OS — RedHat / CentOS / Ubuntu / Solaris / AIX (원본 xlsx 의 OS 정보 열에서 자동 감지)
- **항목**: KISA 가이드 U-01 ~ U-67 (67개)
- **출력**: `data/reports/Unix-{OS}-YYYYMMDD-HHMMSS.xlsx`
  - 원본 열 그대로 보존 + 오른쪽에 `판단결과 / 현황 / 판단근거 / 조치가이드` 4열 추가

---

## 사용법

전제: **Git Bash + Python 3.10+ + [Claude Code](https://claude.com/claude-code) 설치 및 로그인**

```bash
# 전체 점검 (raw data → Claude 분석 → 보고서 생성)
./inspect.sh -os UNIX -file rawdata.xlsx

# 특정 항목만 재점검 (이미 한 번 돌린 뒤 일부만 다시)
./inspect.sh -os UNIX -item U-27,U-28,U-29 -file rawdata.xlsx
```

| 옵션 | 값 | 설명 |
|------|----|------|
| `-os` | `UNIX` | OS 종류 (현재 UNIX 만 지원) |
| `-file` | 경로 (.xlsx) | raw data 파일 |
| `-item` | `U-XX,U-YY,...` | 특정 항목만 재추출하여 재분석 트리거 |

### raw data 형식

xlsx 첫 번째 시트, 1행을 헤더로 사용. 다음 8개 컬럼을 포함해야 한다:

| 컬럼 | 의미 |
|------|------|
| `Hostname` | 점검 대상 서버 이름 |
| `OS 정보` | 운영체제 종류 (RHEL, Ubuntu, Solaris, AIX 등) — 이 열에서 OS 자동 감지 |
| `Code` | KISA 점검 항목 코드 (예: `U-01`) |
| `Name` | 점검 항목 이름 |
| `Result` | 사전 점검 결과 (스캐너/사람이 미리 본 결과, 비어있어도 됨) |
| `Data` | 실제 확인된 설정값·명령어 출력 (판단의 핵심 근거) |
| `Status_Data` | 보조 상태 정보 (파일 존재 여부, 권한, 부가 출력 등) |
| `criteria` | 판단 기준 (KISA 가이드 인용) |

**예시 (3개 행)**:

| Hostname | OS 정보 | Code | Name | Result | Data | Status_Data | criteria |
|----------|---------|------|------|--------|------|-------------|----------|
| host1 | RHEL 8.6 | U-01 | root 원격접속 제한 | 취약 | `PermitRootLogin yes` | 파일 존재 | `PermitRootLogin no` 면 양호 |
| host1 | RHEL 8.6 | U-02 | 패스워드 복잡성 | 취약 | `PASS_MIN_LEN 6` | /etc/login.defs | 8 이상이면 양호 |
| host2 | Ubuntu 22.04 | U-01 | root 원격접속 제한 | 양호 | `PermitRootLogin prohibit-password` | 파일 존재 | `PermitRootLogin no` 면 양호 |

> `Data` 열은 줄바꿈 포함 멀티라인 텍스트일 수 있다 (예: `cat /etc/ssh/sshd_config` 전체 출력 등).

---

### 출력 예시

위 입력의 3행이 다음과 같이 변환된다 — 원본 8열은 그대로 두고, 오른쪽에 4열 추가:

| Hostname | ... (원본 7열 생략) ... | criteria | 판단결과 | 현황 | 판단근거 | 조치가이드 |
|----------|---|---|---------|------|---------|----------|
| host1 | ... | `PermitRootLogin no` 면 양호 | **취약** | root 원격 접속이 허용되어 있으므로 취약 | [확인값] `PermitRootLogin yes`<br>[기준] `PermitRootLogin no` 여야 양호<br>[판단] `yes` ≠ `no` → 취약 | ※ `/etc/ssh/sshd_config` 의 `PermitRootLogin` 을 `no` 로 설정 권고 |
| host1 | ... | 8 이상이면 양호 | **취약** | 패스워드 최소 길이가 기준 미만이므로 취약 | [확인값] `PASS_MIN_LEN 6`<br>[기준] 8 이상이어야 양호<br>[판단] 6 < 8 → 취약 | ※ `/etc/login.defs` 의 `PASS_MIN_LEN` 을 8 이상으로 설정 권고 |
| host2 | ... | `PermitRootLogin no` 면 양호 | **양호** | root 원격 접속이 비밀번호 인증으로 제한되어 있으므로 양호 | [확인값] `PermitRootLogin prohibit-password`<br>[기준] `no` 또는 동등 수준 제한이면 양호<br>[판단] `prohibit-password` 는 비밀번호 로그인 차단으로 동등 수준 → 양호 | (빈칸) |

**각 열의 작성 규칙**:

- **판단결과**: 양호 / 취약 / 확인필요 / N/A 중 하나
- **현황**: `~하므로 양호 / ~하므로 취약 / ~하므로 현장 재확인 요청` 형식의 1~2문장
- **판단근거**: `[확인값] [기준] [판단]` 3단 형식으로 raw data 실제 값과 기준값을 함께 명시
- **조치가이드**: 양호·N/A 면 빈칸, 취약·확인필요 면 `※` 로 시작하는 포괄적 조치 권고

---

## 폴더 구조

```
.
├── inspect.sh                   사용자 진입점
├── CLAUDE.md                    Claude Code 용 프로젝트 가이드
│
├── targets/unix/
│   ├── docs/                    OS별 점검 기준 문서 (Claude 가 읽음)
│   │   ├── redhat/CLAUDE.md
│   │   ├── ubuntu/CLAUDE.md
│   │   ├── solaris/CLAUDE.md
│   │   └── aix/CLAUDE.md
│   └── evaluators/              룰 기반 재판정 코드
│       ├── U-40_NFS.py
│       └── U-45-48_Mail.py
│
├── utils/
│   ├── scripts/
│   │   ├── generate_unix.py     원본 + 결과 병합 → 최종 xlsx
│   │   └── split_csv.py         raw → 코드별 JSON 분할
│   ├── load_input.py            xlsx/csv 입력 로더
│   └── validate_write.py        Claude Code 훅 (원본 열 보호)
│
└── data/                        점검 데이터 (gitignore 전체)
    ├── raw/                     원본 raw data
    ├── results/                 코드별 중간 JSON
    └── reports/                 최종 보고서 xlsx
```

---

## 동작 흐름

```
사용자 ─► inspect.sh -os UNIX -file rawdata.xlsx
              │
              ├─► split_csv.py     raw xlsx 를 코드별 JSON 으로 분할
              │                    (Data 값 같은 호스트는 한 그룹으로 묶어
              │                     Claude 중복 판단 방지)
              │
              ├─► (Claude Code)    각 by_code/U-XX.json 을 읽고
              │                    targets/unix/docs/{OS}/CLAUDE.md 기준으로
              │                    판단 → results_U-XX.json 작성
              │
              ├─► (자동 재판정)     NFS·메일 등은 evaluators/ 코드가
              │                    Claude 판정 위에 덮어쓰기
              │
              └─► generate_unix.py 원본 xlsx + results_*.json 병합
                                   → data/reports/Unix-{OS}-...xlsx
```

---

## 판단 결과 4가지

| 결과 | 의미 |
|------|------|
| 양호 | 기준 충족이 명확히 확인됨 |
| 취약 | 기준 위반이 명확히 확인됨 |
| 확인필요 | raw data 만으로 판단 불가 — 현장 재확인 필요 |
| N/A | 해당 점검 항목 대상이 아님 |

---

## 의존성

- Python 3.10+
- openpyxl
- [Claude Code](https://claude.com/claude-code)
- Git Bash (Windows) 또는 일반 bash

---

## 보안 주의

- `data/` 폴더 전체가 `.gitignore` 처리되어 있어 raw data·결과·보고서는 GitHub 에 올라가지 않음
- 원본 xlsx 는 절대 덮어쓰지 않음 (`validate_write.py` 훅이 차단)
- 점검 결과에는 고객사 식별 정보가 포함될 수 있으므로, 보고서 공유 시 별도 검토 필요

---

## 만든 사람

xum · https://github.com/1-3-1
