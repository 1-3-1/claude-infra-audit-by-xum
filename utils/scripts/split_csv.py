#!/usr/bin/env python3
"""
raw CSV/XLSX → 항목별(U-코드별) 그룹화 파일 생성
동일한 Data값을 가진 호스트를 하나의 그룹으로 묶어
Claude가 중복 판단 없이 항목별로 분석할 수 있도록 함

입력:
  rawdata.csv 또는 rawdata.xlsx (자동 분기)

출력:
  점검결과/by_code/U-01.json        ← 전체 그룹(호스트 매핑용, 항상 생성)
  점검결과/by_code/U-01_batch1.json ← 배치 분할 파일 (100KB 초과 시)
  점검결과/by_code/U-01_batch2.json
  ...
"""
import json, os, sys, hashlib

from utils.load_input import load_rows

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))            # utils/scripts/
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))           # 프로젝트 루트
RESULT_DIR   = os.path.join(PROJECT_ROOT, "data", "results")
BY_CODE_DIR  = os.path.join(RESULT_DIR, "by_code")

BATCH_SIZE_KB = 100   # 이 크기 초과 시 배치 분할
BATCH_GROUPS  = 50    # 배치당 최대 그룹 수


def load_csv(csv_path):
    """CSV 또는 XLSX 자동 분기 로드."""
    rows, _ = load_rows(csv_path)
    return rows


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def split_into_batches(group_list, batch_size=BATCH_GROUPS):
    """그룹 리스트를 배치로 분할. hostnames는 제외하여 Claude 컨텍스트 절약."""
    batches = []
    for i in range(0, len(group_list), batch_size):
        batch = []
        for g in group_list[i:i + batch_size]:
            # Claude에게 보낼 배치: hostnames 제외 (매핑은 전체 파일에 있음)
            batch.append({k: v for k, v in g.items() if k != "hostnames"})
        batches.append(batch)
    return batches


def main():
    args = sys.argv[1:]
    csv_path = None
    items_filter = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--items":
            i += 1
            if i >= len(args):
                print("오류: --items 뒤에 항목 코드가 필요합니다.")
                sys.exit(1)
            # 코드 정규화: "U-2" → "U-02", "u-67" → "U-67"
            def _norm(c):
                c = c.strip().upper()
                if c.startswith("U-") and c[2:].isdigit():
                    return f"U-{int(c[2:]):02d}"
                return c
            items_filter = {_norm(c) for c in args[i].split(",") if c.strip()}
        else:
            csv_path = a
        i += 1

    if not csv_path:
        print("사용법: python split_csv.py rawdata.xlsx [--items U-27,U-28,U-29]")
        sys.exit(1)

    rows = load_csv(csv_path)
    print(f"입력 파일: {csv_path}")
    print(f"전체 행 수: {len(rows)}")
    if items_filter:
        print(f"항목 필터: {sorted(items_filter)} (해당 항목만 재생성)")

    by_code = {}
    for row in rows:
        code = row.get("Code", "").strip()
        if not code:
            continue
        if items_filter and code.upper() not in items_filter:
            continue
        by_code.setdefault(code, []).append(row)

    if items_filter:
        # 필터에 지정됐는데 raw data에 없는 항목 경고
        missing = items_filter - {c.upper() for c in by_code.keys()}
        if missing:
            print(f"경고: raw data에서 찾을 수 없는 항목 → {sorted(missing)}")

    print(f"코드 수: {len(by_code)}")
    os.makedirs(BY_CODE_DIR, exist_ok=True)

    total_hosts  = 0
    total_groups = 0
    batched_codes = []
    cleared_results = []

    for code, code_rows in sorted(by_code.items()):
        groups = {}
        for row in code_rows:
            data_val  = row.get("Data", "").strip()
            data_hash = hashlib.md5(data_val.encode("utf-8", errors="replace")).hexdigest()[:8]

            if data_hash not in groups:
                groups[data_hash] = {
                    "group_id":    data_hash,
                    "Code":        code,
                    "Name":        row.get("Name", ""),
                    "Result":      row.get("Result", ""),
                    "Data":        data_val,
                    "Status_Data": row.get("Status_Data", ""),
                    "criteria":    row.get("criteria", ""),
                    "hostnames":   [],
                }
            groups[data_hash]["hostnames"].append(row.get("Hostname", "").strip())

        group_list    = list(groups.values())
        total_hosts  += len(code_rows)
        total_groups += len(group_list)

        # 전체 파일 저장 (호스트 매핑 포함 — generate_unix.py 가 사용)
        full_path = os.path.join(BY_CODE_DIR, f"{code}.json")
        write_json(full_path, group_list)
        size_kb = os.path.getsize(full_path) / 1024

        # 필터 모드: 기존 results_U-XX.json / 배치 파일 삭제 (재분석 대상 명확화)
        if items_filter:
            old_results = os.path.join(RESULT_DIR, f"results_{code}.json")
            if os.path.exists(old_results):
                os.remove(old_results)
                cleared_results.append(code)
            # 기존 배치 파일도 정리 (개수가 달라질 수 있음)
            import glob as _glob
            for old_batch in _glob.glob(os.path.join(BY_CODE_DIR, f"{code}_batch*.json")):
                os.remove(old_batch)

        if size_kb > BATCH_SIZE_KB:
            # 배치 분할 (hostnames 제외하여 크기 절약)
            batches = split_into_batches(group_list, BATCH_GROUPS)
            for idx, batch in enumerate(batches, 1):
                batch_path = os.path.join(BY_CODE_DIR, f"{code}_batch{idx}.json")
                write_json(batch_path, batch)
            batched_codes.append((code, len(group_list), size_kb, len(batches)))
            print(f"  {code}: {len(code_rows)}호스트 → {len(group_list)}그룹, "
                  f"{size_kb:.0f}KB → {len(batches)}배치로 분할")
        else:
            print(f"  {code}: {len(code_rows)}호스트 → {len(group_list)}그룹, {size_kb:.0f}KB")

    print(f"\n완료: {len(by_code)}개 항목, 총 {total_groups}그룹 (원본 {total_hosts}행)")
    print(f"저장: {BY_CODE_DIR}")

    if batched_codes:
        print(f"\n=== 배치 분할된 항목 ({len(batched_codes)}개) ===")
        for code, g, s, b in batched_codes:
            print(f"  {code}: {g}그룹 → {b}배치 ({code}_batch1.json ~ {code}_batch{b}.json)")

    if cleared_results:
        print(f"\n=== 기존 분석 결과 삭제됨 (재분석 필요) ===")
        for code in cleared_results:
            print(f"  results_{code}.json 삭제")

    if items_filter:
        print(f"""
=== 다음 단계 ===
1. Claude에게 다음 항목 재분석 요청:
   {', '.join(sorted(items_filter))}
   (각 항목의 by_code/U-XX.json 또는 U-XX_batchN.json 읽고 results_U-XX.json 작성)
2. 분석 완료 후 최종 보고서 재생성:
   inspect.sh -os UNIX -file <rawdata.xlsx>
""")
    else:
        print("""
=== 분석 순서 ===
[소형·중형 항목] 파일 1개 → Claude 1번 호출:
  예) U-27.json 읽고 results_U-27.json 작성해줘

[배치 분할 항목] 배치 파일 순서대로:
  예) U-01_batch1.json 읽고 results_U-01.json 에 추가해줘 (배치 1/N)

[최종] inspect.sh -os UNIX -file rawdata.xlsx
""")


if __name__ == "__main__":
    main()
