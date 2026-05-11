"""
U-45/46/47/48 (메일 서비스) cross-reference 평가기.

호스트의 메일 관련 4개 항목 raw data 를 모두 cross-reference 하여
sendmail/postfix/exim 데몬의 실제 구동 여부를 판단한다.

데몬 미구동 판단 시 4개 항목 모두 N/A 처리하고,
판단근거에 어느 항목에서 어떤 증거(ps -ef / Service Disable / 일회성 호출)가 발견됐는지 명시한다.
"""
import re

# ── 패턴: 실제 데몬 구동 (background daemon 또는 25 포트 LISTEN) ──────────
DAEMON_PATTERNS = [
    (re.compile(r'sendmail[^-\n]*\s-bd\b'),     "sendmail -bd (background daemon)"),
    (re.compile(r'/usr/libexec/postfix/master'), "postfix master 프로세스"),
    (re.compile(r'/usr/sbin/postfix\s+start'),   "postfix start"),
    (re.compile(r'\bpostfix/master\b'),          "postfix/master"),
    (re.compile(r'exim[^-\n]*\s-bd\b'),          "exim -bd (background daemon)"),
    (re.compile(r'\.25\s.*LISTEN', re.IGNORECASE), "*.25 LISTEN (netstat)"),
    (re.compile(r':25\s.*LISTEN',   re.IGNORECASE), ":25 LISTEN (ss)"),
    (re.compile(r'\.smtp\s.*LISTEN',re.IGNORECASE), "*.smtp LISTEN"),
]

# ── 패턴: 일회성 호출 (데몬 아님) ─────────────────────────────────────────
ONESHOT_PATTERNS = [
    (re.compile(r'sendmail[^\n]*\s-bt\b'),         "sendmail -bt (address test mode, 일회성)"),
    (re.compile(r'sendmail[^\n]*-FCronDaemon\b'),  "sendmail -FCronDaemon (cron 일회성 호출)"),
    (re.compile(r'sendmail[^\n]*\s-q\b'),           "sendmail -q (큐 처리 일회성)"),
    (re.compile(r'sendmail[^\n]*\s-bv\b'),          "sendmail -bv (verify 일회성)"),
    (re.compile(r'sendmail[^\n]*\s-d0'),            "sendmail -d0 (debug, 버전 확인 용도)"),
]

# ── 패턴: 명시적 비활성 마커 (대소문자 무시) ──────────────────────────────
DISABLED_MARKERS = [
    "sendmail service disable",
    "postfix service disable",
    "exim service disable",
    "smtp 서비스 포트(25)가 비활성화",
    "smtp 서비스가 비활성화",
    "포트(25)가 비활성화",
    "메일 서비스가 비활성화",
    "메일 서비스를 구동하고 있지 않",
    "smtp 서비스가 구동 중이지 않",
    "smtp 서비스가 구동되고 있지 않",
    "메일 데몬이 실행되지 않",
    "메일 데몬을 사용하고 있지 않",
    "실행 중인 메일 서비스가 없",
    "실행 중인 smtp 관련 프로세스가 없",
    "프로세스가 발견되지 않",
    "프로세스가 존재하지 않",
    "점검 대상 서비스가 구동 중이지 않",
    "구동 중인 메일",
    "25 포트가 리스닝 상태가 아닙",
    "/etc/mail/sendmail.cf 파일이 없",
    "sendmail.cf 파일이 존재하지 않",
]


def _scan(codes_data, patterns_with_label):
    """codes_data {code: data} 에서 각 패턴 매칭. (code, label) 리스트 반환."""
    found = []
    for code, data in codes_data.items():
        if not data:
            continue
        for pat, label in patterns_with_label:
            if pat.search(data):
                found.append((code, label))
                break  # 같은 코드에서 같은 카테고리 중복 방지
    return found


def _scan_markers(codes_data):
    """비활성 마커 매칭 (대소문자 무시). (code, marker_text) 리스트 반환."""
    found = []
    for code, data in codes_data.items():
        if not data:
            continue
        data_lower = data.lower()
        for m in DISABLED_MARKERS:
            if m in data_lower:
                found.append((code, m))
                break
    return found


def detect_mail_daemon_status(codes_data):
    """
    codes_data: {U-45: data_text, U-46: ..., U-47: ..., U-48: ...}

    Returns:
        ('running', evidence_list)     — 데몬 구동 중 (LLM 결과 유지)
        ('not_running', evidence_list) — 데몬 미구동 (4개 항목 모두 N/A 처리)
        ('unknown', [])                — 판단 불가 (LLM 결과 유지)

    evidence_list: [(code, evidence_str), ...]
    """
    daemon_evidence = _scan(codes_data, DAEMON_PATTERNS)
    if daemon_evidence:
        return 'running', daemon_evidence

    oneshot_evidence  = _scan(codes_data, ONESHOT_PATTERNS)
    disabled_evidence = _scan_markers(codes_data)

    # 1) 비활성 마커가 충분 → 미구동 확정
    # 2) 일회성 호출만 있고 데몬 패턴 없음 → 미구동
    if len(disabled_evidence) >= 1 or oneshot_evidence:
        return 'not_running', disabled_evidence + oneshot_evidence

    return 'unknown', []


def get_na_result(evidence_list):
    """N/A 판정용 결과 dict 생성. evidence_list 를 판단근거에 명시."""
    evidence_lines = "\n".join(
        f"  - {code}: {ev}" for code, ev in evidence_list
    ) or "  - (증거 없음)"

    return {
        "판단결과": "N/A",
        "판단근거": (
            "[확인값] 호스트 단위 cross-reference — 메일 데몬 미구동 증거:\n"
            f"{evidence_lines}\n"
            "[기준] 메일 데몬(sendmail -bd / postfix master / exim -bd) 구동 중이고 "
            "25 포트 LISTEN 상태일 때만 점검 대상\n"
            "[판단] 메일 서비스 미구동 → N/A"
        )
    }
