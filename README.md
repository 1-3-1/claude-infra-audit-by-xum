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

xlsx 첫 번째 시트, 1행 헤더, 다음 컬럼 포함:
`Hostname, OS 정보, Code, Name, Result, Data, Status_Data, criteria`

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
