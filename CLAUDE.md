# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 프로젝트 목적
인프라 점검 raw data(xlsx)를 받아 보안 취약점을 진단하고 결과 보고서(xlsx)를 작성한다.
기준 문서: 2026 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드

---

## 입력 파일 규칙
- 입력 형식: **CSV** 또는 **XLSX** (`load_input.py`가 확장자로 자동 분기, 권장: xlsx)
  - CSV 인코딩: utf-8-sig / euc-kr / cp949 / utf-8 자동 감지
  - XLSX: 첫 번째 시트만 사용, 1행을 헤더로 인식, openpyxl로 읽음 (자동 타입 변환 없음)
- 출력 형식: **XLSX** (`openpyxl`로 저장)
- 원본 열 구조 (예: 8개): `Hostname, OS 정보, Code, Name, Result, Data, Status_Data, criteria`
- 출력: **원본 모든 열을 변경 없이 그대로 보존**하고, 오른쪽에 **신규 열 4개를 추가**
- **원칙**: 원본 데이터(왼쪽 열들)는 절대 건드리지 않는다 — 누락·삭제·순서변경 금지
- `generate_unix.py`는 원본 헤더를 **동적으로** 읽어 보존하므로 8개 열이든 7개 열이든 자동 대응

| 열 위치 | 열 이름 | 내용 |
|---------|---------|------|
| 1~N | 원본 열 (그대로 보존) | Hostname, [OS 정보,] Code, Name, Result, Data, Status_Data, criteria 등 |
| N+1 | 판단결과 | 양호 / 취약 / 확인필요 / N/A |
| N+2 | 현황 | 실제 확인값과 기준을 인용한 1~2문장 현황 요약 |
| N+3 | 판단근거 | Data 기반 상세 근거 (기준 문서 기준값 명시) |
| N+4 | 조치가이드 | 취약·확인필요 시 ※ 로 시작하는 포괄적 조치 권고 |

---

## 판단 결과 기준

| 결과 | 사용 조건 |
|------|----------|
| **양호** | Data에서 판단 기준 충족이 명확히 확인된 경우 |
| **취약** | Data에서 판단 기준 위반이 명확히 확인된 경우 |
| **확인필요** | Data가 불충분하거나 "파일 내용 확인 필요"가 명시된 경우, 또는 현장 확인 없이 판단 불가한 경우 |
| **N/A** | 해당 항목의 점검 대상이 아닌 경우 (예: Data 에 "해당사항 없음" 명시) |

---

## 확인필요 작성 규칙

판단결과가 **확인필요**인 경우:
- 판단근거: "현장 재확인 필요 — [구체적으로 무엇을 확인해야 하는지 상세히 기술]"
- 조치가이드: 현장에서 실행할 확인 명령어 또는 확인 절차를 명시

**확인필요 판단근거 작성 예시:**
```
현장 재확인 필요 —
  확인 대상: /etc/login.defs 파일 내 PASS_MAX_DAYS, PASS_MIN_LEN 설정값
  확인 이유: raw data 에 비밀번호 정책 설정이 확인되지 않아 실제 파일 내용 직접 조회 필요
  확인 명령어: grep -E 'PASS_MAX_DAYS|PASS_MIN_LEN' /etc/login.defs
  판단 기준: PASS_MAX_DAYS<=90 이고 PASS_MIN_LEN>=8 이면 양호, 그 외 취약
```

---

## 판단근거 작성 규칙

- raw data에서 확인된 **실제 값**을 반드시 명시한다. 추정 금지.
- 기준 문서의 **양호/취약 기준값**을 함께 명시한다.
- 형식 예시:
  ```
  [확인값] /etc/shadow 권한: -rw-r--r-- (644)
  [기준] 400 이하여야 양호
  [판단] 644 > 400 → 취약
  ```

---

## 현황 작성 규칙

- 특정 파일명·경로·수치를 나열하지 않는다.
- `~하므로 양호 / ~하므로 취약 / ~하므로 현장 재확인 요청` 형식으로 작성한다.
- `generate_unix.py` 의 현황 핸들러에 U 코드·판단결과별 문구가 정의되어 있다. 새 항목/문구는 핸들러를 점진적으로 확장한다.
- 작성 예시:
  ```
  양호: 패스워드 정책이 기준을 충족하므로 양호
  취약: 비밀번호 파일의 접근 권한이 기준을 초과하므로 취약
  확인필요: 설정값을 현장에서 직접 확인해야 하므로 현장 재확인 요청
  N/A: 해당 서버 미해당 항목
  ```

---

## 조치가이드 작성 규칙

- **양호**: 빈칸으로 둔다.
- **N/A**: 빈칸으로 둔다.
- **취약·확인필요**: `※` 로 시작하는 **포괄적 조치 권고문**을 작성한다.
  - 특정 경로나 명령어 대신 일반적 설정 항목명과 기준값을 명시한다.
  - 담당자가 방향을 파악할 수 있는 수준으로 작성한다.
- 작성 예시:
  ```
  ※ /etc/shadow 파일의 접근 권한을 400 이하로 설정 권고
  ※ 불필요 서비스(rlogin, telnet 등)는 비활성화하고, 필요 시 SSH 등 보안 프로토콜 사용 권고
  ```

---

## ⚠️ 점검 기준 참조 규칙 (필수)

Unix(`U-XX`) 점검 항목을 평가할 때 — 직접 평가하든, 서브에이전트에게 위임하든 — 다음을 반드시 지킨다:

1. **기준은 해당 `CLAUDE.md` 파일을 Read 도구로 직접 읽어 확인**한다. 기억·이전 대화 요약·컴팩트 summary에서 기준을 가져오지 않는다.
   - 요약은 손실 압축이라 selector 목록·권한 임계값·예외조건이 누락되거나 변형되어 있을 수 있다.
   - 한 번 잘못 옮긴 기준으로 수백 개 호스트가 오판될 수 있다.
2. 서브에이전트에게 점검을 위임할 때는 **기준을 프롬프트에 인라인으로 박지 않는다**. 대신 다음 형식으로 지시한다:
   > "판단 기준은 `unix/{OS}/CLAUDE.md`의 U-XX 섹션을 Read 도구로 읽어 그대로 적용하라.
   >  요약·재해석·축약 금지. 명시된 selector/조건이 하나라도 누락되면 취약으로 판정."
3. 여러 OS가 섞인 점검(`Unix-Mixed-...xlsx`)이면 OS별로 해당 `unix/{OS}/CLAUDE.md` **모두**를 읽도록 지시한다 (RHEL/Ubuntu/Solaris/AIX 4개 파일).
4. 분석 완료 후 이중검토 단계에서 **양호 판정 1~2건을 샘플링**해 해당 OS의 `CLAUDE.md` 기준과 직접 대조한다. 미스매치 발견 시 그 코드 전체를 즉시 재점검 트리거한다.

---

## 이중검토 지침 (필수)

점검 결과 CSV 생성 후 **반드시** 이중검토를 수행한다. 이중검토는 추가 AI 호출 없이 이 대화 세션에서 직접 수행한다.

### 검토 절차

1. **판단결과 정확성 검토**: 모든 행의 `판단결과`가 `판단근거`와 논리적으로 일치하는지 확인한다.
   - `[확인값]`이 `[기준]`을 충족하면 양호, 위반하면 취약
   - Data에 "파일 내용 확인 필요" 등이 있으면 확인필요
   - Data 에 "해당사항 없음" 명시되면 N/A

2. **교차 일관성 검토**: 동일 항목에 대해 호스트 간 결과가 다를 경우 근거가 실제로 다른지 확인한다.
   - 예: host1 U-12=취약, host2 U-12=양호 → 설정 파일 내용이 실제로 다른지 확인

3. **현황 텍스트 품질 검토**: 현황 열이 판단결과를 올바르게 요약하는지 확인한다.
   - 취약 항목의 현황이 양호 표현으로 시작하는 경우
   - 현황이 섹션 헤더(경로:)로 시작하는 경우

### 검토 후 처리

- **오판 발견 시**: `data/results/results_U-XX.json` 해당 항목을 수정 후 `inspect.sh -os UNIX -file ...` 재실행
- **현황 텍스트 오류 시**: `generate_unix.py` 의 현황 핸들러 수정 후 재실행
- 이중검토 결과를 사용자에게 보고한다 (오판 건수, 수정 내용 포함)

---

## 처리 흐름

### Unix OS 점검 (`generate_unix.py`)
1. 원본 xlsx 헤더를 **동적으로** 읽어 보존 (8개 열이든 7개 열이든 자동)
2. `data/results/by_code/U-XX.json` + `data/results/results_U-XX.json` 로드
3. (Hostname, Code) 키로 판단결과·판단근거 매칭
4. U-코드별 GUIDE_MAP으로 조치가이드 생성
5. **출력 파일명**: `OS 정보` 열에서 OS 자동 감지
   - 단일 OS → `Unix-{OS}-YYYYMMDD-HHMMSS.xlsx` (예: `Unix-RHEL-...xlsx`)
   - 다중 OS → `Unix-Mixed-YYYYMMDD-HHMMSS.xlsx`
6. 중간 JSON 파일은 `data/results/` 폴더에 보관

### Unix 특정 항목 재점검 (`split_csv.py --items`)
1. 지정한 항목들의 행만 raw xlsx에서 추출
2. Data 해시(MD5 8자리)로 중복 그룹화
3. `data/results/by_code/U-XX.json` 재생성 (기존 배치 파일 삭제)
4. `data/results/results_U-XX.json` 삭제 (재분석 대상 명확화)
5. 다음 단계 안내 출력 (Claude에게 분석 요청 → `inspect.sh -os UNIX -file ...`)

### CLI 사용법

옵션은 모두 `-키 값` 형식. 입력은 xlsx 또는 csv, **출력은 xlsx**.

```bash
# Unix OS 점검 → 최종 보고서(xlsx) 생성
inspect.sh -os UNIX -file rawdata.xlsx

# 특정 항목 재점검 (JSON 재생성 + 기존 results 삭제 → Claude 재분석 트리거)
inspect.sh -os UNIX -item U-27,U-28,U-29 -file rawdata.xlsx
```

| 옵션 | 값 | 설명 |
|------|----|------|
| `-os` | `UNIX` | OS 종류 (현재 UNIX 만 지원) |
| `-file` | 경로 (.xlsx) | raw data 파일 (xlsx 전용) |
| `-item` | `U-XX,U-YY,...` | 특정 항목만 재추출 → JSON 재생성 → 재분석 트리거 |

#### `-item` 동작 흐름

1. `inspect.sh -os UNIX -item U-27,U-28 -file rawdata.xlsx` 실행
   → `data/results/by_code/U-27.json`, `U-28.json` 재생성 (해당 항목 행만 xlsx에서 추출, Data 해시로 그룹화)
   → 기존 `data/results/results_U-27.json`, `results_U-28.json` 삭제
2. Claude에게 재분석 요청: "U-27, U-28 분석 후 results 파일 작성"
3. 분석 완료 후 최종 보고서 재생성: `inspect.sh -os UNIX -file rawdata.xlsx`
   → 모든 항목(재분석된 것 포함) 포함된 `Unix-{OS}-YYYYMMDD-HHMMSS.xlsx` 출력

---

## 디렉터리 구조

```
클로바보다클로드/
├── CLAUDE.md                  # 이 파일 (프로젝트 메인 가이드)
├── inspect.sh                 # ⭐ 유일한 사용자 진입점 (Git Bash 등에서 실행)
│
├── targets/                   # 🎯 점검 대상 (도메인 분류)
│   └── unix/
│       ├── docs/              # OS별 점검 기준 문서
│       │   ├── CLAUDE.md
│       │   ├── aix/CLAUDE.md
│       │   ├── redhat/CLAUDE.md
│       │   ├── solaris/CLAUDE.md
│       │   └── ubuntu/CLAUDE.md
│       └── evaluators/        # 항목별 재판정 코드
│           ├── __init__.py    # importlib 로 하이픈 파일명 우회 + 깔끔한 이름 재노출
│           ├── U-40_NFS.py    # U-40 NFS 접근통제
│           └── U-45-48_Mail.py  # U-45~48 메일 서비스 cross-reference
│
├── utils/                     # 🔧 공용 유틸 + 내부 진입점
│   ├── __init__.py
│   ├── scripts/               # inspect.sh 가 호출하는 내부 진입점
│   │   ├── generate_unix.py   # Unix OS 점검 보고서 생성
│   │   └── split_csv.py       # -item 옵션 시 항목별 재추출
│   ├── load_input.py          # xlsx/csv 입력 로더
│   └── validate_write.py      # Claude Code PreToolUse 훅 (.claude/settings.json)
│
├── data/                      # 💾 점검 데이터 (gitignore, 전체)
│   ├── raw/                   # 원본 raw data
│   ├── results/               # 점검 중간 결과 JSON
│   └── reports/               # 최종 보고서 xlsx
│
└── _scratch/                  # ⚠️ 일회성 분석 스크립트 (gitignore)
```

### 진입점 호출 흐름

```
사용자
   ↓ ./inspect.sh -os UNIX -file rawdata.xlsx
inspect.sh
   ↓ cd 프로젝트루트 && python -m utils.scripts.generate_unix
utils/scripts/generate_unix.py
   ↓ from targets.unix.evaluators import evaluate_nfs, ...
   ↓ from utils.load_input import load_rows
   ↓ 결과 → data/reports/Unix-XXX.xlsx
```

### `utils/` 폴더 규칙 (필수)

직접 실행되지 않고 **다른 코드가 import** 하는 보조 모듈, 또는 **Claude Code 훅** 으로 호출되는 스크립트는 `utils/` 하위에 둔다.

| 종류 | 예시 | 호출 방식 |
|------|------|-----------|
| import 되는 헬퍼 | `utils/load_input.py` | `from utils.load_input import load_rows` |
| 훅 스크립트 | `utils/validate_write.py` | `.claude/settings.json` 에서 절대경로로 호출 |

새 보조 파일 추가 시 반드시 `utils/` 하위에 만들고, import 경로는 `from utils.xxx import ...` 형식으로 사용한다.

**루트에 남는 파일은 `inspect.sh` 와 `CLAUDE.md` 만**: 모든 Python 진입점은 `utils/scripts/` 안. `inspect.sh` 가 `python -m utils.scripts.xxx` 형식으로 호출.

### `evaluators/` 폴더 규칙 (필수)

NFS·메일처럼 **AI 판정만으로 부족해 코드로 재판정해야 하는 항목** 은 반드시 `evaluators/{서버종류}/U-XX_이름.py` 형식으로 생성한다.

| 구분 | 위치 |
|------|------|
| Unix 점검 항목 | `targets/unix/evaluators/U-XX_이름.py` |
| 여러 코드 묶인 항목 | `targets/unix/evaluators/U-45-48_Mail.py` 처럼 범위 표기 |

파일명에 하이픈이 들어가면 `import` 가 안 되므로, **`targets/{대상}/evaluators/__init__.py`** 의 `_MODULES` dict 에 등록하면 자동으로 깔끔한 이름으로 재노출된다. 호출자는 `from targets.unix.evaluators import evaluate_nfs` 식으로 사용.

새 evaluator 추가 절차:
1. `evaluators/{서버}/U-XX_이름.py` 작성 (`evaluate_xxx()` 등 함수 정의)
2. `evaluators/{서버}/__init__.py` 의 `_MODULES` 와 외부 노출 라인 갱신
3. `generate_unix.py` 의 `load_results()` 에서 해당 코드 매칭 시 호출

### `_scratch/` 폴더 규칙 (필수)

분석·재점검·일회성 스크립트는 **반드시 `_scratch/` 하위에 생성**한다. 메인 디렉터리는 도구의 재사용 모듈만 유지.

| 구분 | 위치 | 예시 |
|------|------|------|
| **도구 모듈** (매 실행 호출됨) | 메인 디렉터리 또는 `evaluators/` | `generate_unix.py`, `evaluators/unix/U-40_NFS.py` |
| **일회성 스크립트** (한 번 돌리고 끝) | `_scratch/` | `analyze_uXX.py`, `_eval_*.py`, `_gen_*.py`, `recheck_*.py`, `add_*_columns.py` |

판단 기준: 다음 중 하나라도 해당하면 `_scratch/` 행.
- 절대 경로 하드코딩 (`C:/Users/sumin/...`)
- 특정 시점 데이터 의존 (`_host_os_map.json` 등 임시 파일)
- `generate_unix.py` 가 호출하지 않음
- 결과(`results_U-XX.json`)만 만들고 다시 실행할 일 없음

`_scratch/` 는 `.gitignore` 로 GitHub 에 안 올라간다.

- 원본 xlsx 는 절대 덮어쓰지 않는다.
- 최종 보고서는 항상 `data/reports/` 폴더에 저장한다.
- 파일명 형식: `Unix-{OS}-{YYYYMMDD}-{HHMMSS}.xlsx` (예: `Unix-RHEL-20260511-143022.xlsx`)
- 다중 OS 혼합 입력 시: `Unix-Mixed-{YYYYMMDD}-{HHMMSS}.xlsx`

---

## 기타 규칙
- Data 컬럼에 "해당사항 없음" 또는 "Apache, Nginx, IIS, WebtoB 점검 항목으로 해당사항 없음" 등이 명시된 경우 → **N/A**
- 동일 호스트의 동일 항목이 여러 인스턴스(경로)에 걸쳐 있을 경우, 하나라도 취약하면 **취약**으로 판단한다.
- 판단근거에는 모든 인스턴스의 확인값을 나열한다.
