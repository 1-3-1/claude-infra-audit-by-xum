#!/usr/bin/env python3
"""
PreToolUse 훅 — Write 실행 전 원본 CSV 열 보호 검증
- 원본 7개 열(Hostname~criteria)이 변경된 채로 CSV를 쓰려 하면 차단
- 원본 데이터 파일 경로(점검결과보고서/ 외 위치)에 직접 쓰려 하면 차단
"""
import json, sys, csv, io, os

# 환경에 따라 stdout 인코딩 강제 설정 (Windows 터미널 한글 출력)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf-8-sig"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.normcase(os.path.normpath(os.path.join(SCRIPT_DIR, "점검결과보고서")))
RESULT_DIR = os.path.join(SCRIPT_DIR, "점검결과")

ORIGINAL_COLS = ["Hostname", "Code", "Name", "Result", "Data", "Status_Data", "criteria"]


def load_source_data():
    """점검결과/ 폴더의 원본 호스트 JSON에서 원본 열 값 로드"""
    source = {}
    if not os.path.isdir(RESULT_DIR):
        return source
    for hf in os.listdir(RESULT_DIR):
        if not hf.endswith(".json") or hf.startswith("results_"):
            continue
        p = os.path.join(RESULT_DIR, hf)
        with open(p, encoding="utf-8") as f:
            for row in json.load(f):
                key = (row.get("Hostname", ""), row.get("Code", ""))
                source[key] = {c: row.get(c, "") for c in ORIGINAL_COLS}
    return source


def main():
    # 바이너리로 읽어 BOM 및 인코딩 문제 방지
    try:
        raw_bytes = sys.stdin.buffer.read()
        raw = raw_bytes.decode("utf-8-sig").strip()
    except Exception:
        raw = sys.stdin.read().strip()

    if not raw:
        sys.exit(0)

    try:
        hook_input = json.loads(raw)
    except Exception:
        sys.exit(0)

    tool_name  = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    if tool_name != "Write":
        sys.exit(0)

    file_path = tool_input.get("file_path", "")
    content   = tool_input.get("content", "")

    if not file_path.lower().endswith(".csv"):
        sys.exit(0)

    # 슬래시 통일 후 소문자 비교 (한글 경로 os.path 인코딩 문제 우회)
    norm_path = file_path.replace("\\", "/").lower()

    # ── 규칙 1: 점검결과보고서/ 외 경로에 CSV 쓰기 차단 ──────────────────
    in_report_dir = "점검결과보고서" in file_path.replace("\\", "/").split("/")
    if not in_report_dir:
        msg = (
            "[원본 보호] 차단: 보고서 폴더 외 경로에 CSV 쓰기가 감지됐습니다.\n"
            f"  대상 경로: {file_path}\n"
            f"  허용 경로: {REPORT_DIR}\n"
            "  원본 CSV는 절대 덮어쓰지 않습니다. 점검결과보고서/ 폴더에 저장하세요."
        )
        print(msg)
        sys.exit(2)

    # ── 규칙 2: 보고서 CSV 내 원본 열 변경·삭제 여부 검증 ────────────────
    source = load_source_data()
    if not source:
        sys.exit(0)

    try:
        # UTF-8 BOM 제거 (Excel 호환 저장 시 BOM이 포함되어 첫 열명이 깨질 수 있음)
        reader = csv.DictReader(io.StringIO(content.lstrip('﻿')))
        out_rows = list(reader)
        out_keys = {(r.get("Hostname", ""), r.get("Code", "")) for r in out_rows}

        violations = []

        # 검증 A: 원본 행이 출력에서 누락되거나 알 수 없는 행이 추가된 경우
        missing  = [k for k in source   if k not in out_keys]
        extra    = [k for k in out_keys if k not in source]
        if missing:
            violations.append(f"  원본 {len(missing)}개 행이 출력 CSV에 없음 (삭제 또는 Hostname/Code 변조 의심)")
        if extra:
            violations.append(f"  출력 CSV에 원본에 없는 {len(extra)}개 행 발견 (Hostname/Code 변조 의심)")

        # 검증 B: 공통 키에서 원본 열 값 변경 감지
        for row in out_rows:
            key = (row.get("Hostname", ""), row.get("Code", ""))
            if key not in source:
                continue
            for col in ORIGINAL_COLS:
                orig = source[key].get(col, "")
                new  = row.get(col, "")
                if orig.strip() != new.strip():
                    violations.append(f"  {key[0]}/{key[1]} [{col}]: 원본값이 변경됨")

        if violations:
            print("[원본 보호] 차단: 원본 데이터 변경이 감지됐습니다.")
            for v in violations[:10]:
                print(v)
            if len(violations) > 10:
                print(f"  ... 외 {len(violations) - 10}건")
            sys.exit(2)
    except Exception as e:
        print(f"[원본 보호] 검증 오류: {e} — 쓰기를 허용합니다.")
        sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
