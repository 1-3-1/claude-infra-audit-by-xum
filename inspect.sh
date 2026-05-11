#!/bin/bash

OS=""
RAWDATA=""
ITEMS=""

# ── 옵션 파싱 ─────────────────────────────────────────────
# 형식: -os UNIX  /  -file <경로.xlsx>  /  -item U-27,U-28,U-29
# 호환: -UNIX
while [ $# -gt 0 ]; do
    case "${1^^}" in
        -OS)
            shift
            OS="${1,,}"
            ;;
        -FILE)
            shift
            RAWDATA="$1"
            ;;
        -ITEM|-ITEMS)
            shift
            ITEMS="$1"
            ;;
        -UNIX)    OS="unix" ;;
        -UBUNTU|-REDHAT|-SOLARIS|-AIX) ;;
        -*)
            echo "경고: 알 수 없는 옵션 → $1"
            ;;
        *)
            RAWDATA="$1"
            ;;
    esac
    shift
done

# Windows 백슬래시 → 슬래시 변환
RAWDATA="${RAWDATA//\\//}"

# Windows 드라이브 문자 변환: C:/... → /c/...
if [[ "$RAWDATA" =~ ^([A-Za-z]):/(.*) ]]; then
    RAWDATA="/${BASH_REMATCH[1],,}/${BASH_REMATCH[2]}"
fi

# 절대 경로로 변환
RAWDATA_ABS=$(realpath "$RAWDATA" 2>/dev/null || echo "$RAWDATA")

print_usage() {
    echo "사용법:"
    echo "  inspect.sh -os UNIX -file <rawdata.xlsx>"
    echo "  inspect.sh -os UNIX -item U-27,U-28,U-29 -file <rawdata.xlsx>"
    echo ""
    echo "옵션:"
    echo "  -os UNIX                    : OS 종류 (현재 UNIX 만 지원)"
    echo "  -file <경로>                 : raw data 파일 (.xlsx 권장, .csv 도 지원)"
    echo "  -item U-XX,U-YY,...         : 특정 항목만 재추출 → JSON 재생성 → 재분석 트리거"
}

# ── Unix OS 점검 모드 ─────────────────────────────────────
if [ "$OS" != "unix" ]; then
    echo "오류: -os UNIX 를 지정하세요."
    print_usage
    exit 1
fi

if [ -z "$RAWDATA" ]; then
    echo "오류: rawdata 파일을 지정하세요. (-file <경로.xlsx>)"
    print_usage
    exit 1
fi
if [ ! -f "$RAWDATA_ABS" ]; then
    echo "오류: 파일을 찾을 수 없습니다 → $RAWDATA_ABS"
    exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -n "$ITEMS" ]; then
    # ── -item 모드: 특정 항목만 JSON 재생성 (기존 results 삭제) ──
    echo "==================================="
    echo " 모드     : 특정 항목 JSON 재생성"
    echo " Raw Data : $RAWDATA_ABS"
    echo " 항목 필터: $ITEMS"
    echo "==================================="
    ( cd "$SCRIPT_DIR" && python -m utils.scripts.split_csv "$RAWDATA_ABS" --items "$ITEMS" )
    exit $?
fi

# ── 기본 모드: 최종 보고서(xlsx) 생성 ──
echo "==================================="
echo " 점검 모드: Unix OS 점검 (최종 보고서 생성)"
echo " Raw Data : $RAWDATA_ABS"
echo " 기준 경로: $SCRIPT_DIR/targets/unix/docs/ (OS는 원본 xlsx에서 자동 감지)"
echo "==================================="
( cd "$SCRIPT_DIR" && python -m utils.scripts.generate_unix "$RAWDATA_ABS" )
exit $?
