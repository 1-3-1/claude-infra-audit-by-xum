"""
U-40 (NFS 접근통제) 판정 로직.

규칙 (KISA 기준 + 사용자 합의):
  양호 조건 (모두 만족):
    1) access= 또는 ro=/rw= 에 호스트 목록이 명시되어 있음 (everyone 공유 아님)
    2) root= 옵션이 없거나 명백히 필요한 호스트로 한정됨 (1~2개)
    3) Linux의 경우 no_root_squash 가 와일드카드와 결합되지 않음

  취약 조건 (하나라도 해당):
    1) access/rw=/ro= 옵션 없이 단순 'rw'/'ro' 만으로 공유 → everyone
    2) Linux의 경우 호스트가 '*' 또는 와일드카드
    3) root= 호스트가 3개 이상 (광범위)
    4) no_root_squash + 와일드카드 호스트

  sec=sys 허용 여부는 참고 정보로만 기록하며 판정에 직접 반영하지 않는다.
"""
import re

NFS_DAEMON_PATTERNS = [
    re.compile(r'/usr/sbin/nfsd\b'),
    re.compile(r'/usr/lib/nfs/nfsd\b'),
    re.compile(r'\[nfsd\]'),
]

NFS_DISABLED_MARKERS = [
    "NFS Service Disable",
    "구동 중인 NFS 관련 프로세스가 없습니다",
    "NFS 서비스를 구동하고 있지 않으므로",
]

EXPORTS_SECTION_HEADERS = [
    "/etc/exports 설정 내용",
    "/etc/exports 파일 설정",
    "cat /etc/exports",
]

SECTION_END_PREFIXES = ("■", "①", "②", "③")
SEPARATOR_RE = re.compile(r"^[\-=]{3,}$")
DELIM_BLOCK_RE = re.compile(r"^-=(-=)+-?$")


def is_nfs_running(data_text):
    return any(p.search(data_text) for p in NFS_DAEMON_PATTERNS)


def is_nfs_disabled_marked(data_text):
    return any(m in data_text for m in NFS_DISABLED_MARKERS)


def extract_export_lines(data_text):
    """raw Data 텍스트에서 /etc/exports 본문에 해당하는 라인만 추출.
       헤더 직후의 '----' 구분선은 섹션 종료가 아니라 장식이므로 무시한다."""
    lines = []
    in_section = False
    for raw_line in data_text.splitlines():
        line = raw_line.strip()

        if any(h in raw_line for h in EXPORTS_SECTION_HEADERS):
            in_section = True
            continue

        if not in_section:
            continue

        # 장식용 구분선은 섹션을 종료하지 않음
        if SEPARATOR_RE.match(line):
            continue

        # 진짜 섹션 종료 신호
        if DELIM_BLOCK_RE.match(line):
            in_section = False
            continue
        if line.startswith(SECTION_END_PREFIXES):
            in_section = False
            continue
        if line.startswith("$ ") or line.startswith("# "):
            in_section = False
            continue

        if not line:
            continue
        if line.startswith("#"):
            continue
        if "cannot open" in line or "No such file" in line:
            continue
        if any(s in line for s in ("설정 내용이 없", "파일이 없", "파일이 존재하지 않")):
            continue

        if line.startswith("/"):
            lines.append(line)

    return lines


def parse_aix_options(opts_str):
    """AIX 옵션 'sec=sys:krb5p,rw,root=trustedhost' → dict."""
    result = {}
    for part in opts_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[part] = True
    return result


def parse_export_line(line):
    """한 줄의 /etc/exports 항목을 파싱.
       AIX: '/path -opt1=val,opt2,...'
       Linux: '/path host(opts) host2(opts2)'
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # AIX 형식: dash로 시작하는 옵션 블록
    aix_match = re.match(r"^(/\S+)\s+-(.+)$", line)
    if aix_match:
        return {
            "syntax": "aix",
            "path": aix_match.group(1),
            "raw_opts": aix_match.group(2),
            "options": parse_aix_options(aix_match.group(2)),
        }

    # Linux 형식: 'host(opts)' 토큰
    linux_match = re.match(r"^(/\S+)\s+(.+)$", line)
    if linux_match:
        path = linux_match.group(1)
        rest = linux_match.group(2)
        clients = []
        for m in re.finditer(r"(\S+?)\(([^)]*)\)", rest):
            host = m.group(1)
            opts_str = m.group(2)
            options = {o.strip() for o in opts_str.split(",") if o.strip()}
            clients.append({
                "host": host,
                "opts_str": opts_str,
                "options": options,
            })
        return {
            "syntax": "linux",
            "path": path,
            "raw": rest,
            "clients": clients,
        }

    return None


def evaluate_aix_entry(parsed):
    issues = []
    notes = []
    opts = parsed["options"]
    path = parsed["path"]

    has_access = "access" in opts
    rw_val = opts.get("rw")
    ro_val = opts.get("ro")
    rw_unrestricted = rw_val is True
    ro_unrestricted = ro_val is True
    has_rw_list = isinstance(rw_val, str)
    has_ro_list = isinstance(ro_val, str)

    if not has_access and not has_rw_list and not has_ro_list:
        if rw_unrestricted:
            issues.append(f"{path}: 'rw' 가 호스트 제한 없이 지정됨 → 모든 호스트 RW 마운트 가능")
        elif ro_unrestricted:
            issues.append(f"{path}: 'ro' 가 호스트 제한 없이 지정됨 → 모든 호스트 RO 마운트 가능")
        else:
            issues.append(f"{path}: 접근 호스트(access=/rw=/ro=) 미지정")

    root_val = opts.get("root")
    if isinstance(root_val, str):
        hosts = [h for h in root_val.split(":") if h]
        if len(hosts) >= 3:
            issues.append(f"{path}: root={root_val} — {len(hosts)}개 호스트에 root squash 예외 (광범위)")
        else:
            notes.append(f"{path}: root={root_val} — 단일/소수 호스트 root 예외 (운영 필요성 확인 권고)")

    sec_val = opts.get("sec")
    if isinstance(sec_val, str) and "sys" in sec_val.split(":"):
        notes.append(f"{path}: sec=sys 허용 — 약한 인증 가능 (krb5p 단독 권장, 판정에는 미반영)")

    return issues, notes


def evaluate_linux_entry(parsed):
    issues = []
    notes = []
    path = parsed["path"]

    if not parsed["clients"]:
        # 'host' (옵션 없음) 형식만 있는 경우 처리
        tokens = parsed["raw"].split()
        wildcard_no_opts = any(t in ("*", "0.0.0.0/0") for t in tokens)
        if wildcard_no_opts:
            issues.append(f"{path}: 호스트 와일드카드 '*' 사용 → 모든 호스트 마운트 가능")
        elif tokens:
            notes.append(f"{path}: 호스트 {tokens} (옵션 미지정, 기본값 적용)")
        return issues, notes

    for c in parsed["clients"]:
        host = c["host"]
        opts = c["options"]

        is_wildcard = host == "*" or host.startswith("*.") or host in ("0.0.0.0/0", "::/0")

        if is_wildcard:
            if "rw" in opts:
                issues.append(f"{path}: 호스트 '{host}' 와일드카드에 rw 허용 → 모든 호스트 RW")
            else:
                issues.append(f"{path}: 호스트 '{host}' 와일드카드 → 모든 호스트 마운트 가능")

        if "no_root_squash" in opts:
            if is_wildcard:
                issues.append(f"{path}: no_root_squash + 와일드카드 호스트 → 모든 클라이언트 root 권한 부여")
            else:
                notes.append(f"{path}: 호스트 '{host}'에 no_root_squash 적용 (운영 필요성 확인 권고)")

        if "insecure" in opts:
            notes.append(f"{path}: insecure 옵션 — 1024 이상 포트 허용 (보안 강화 시 제거 권고)")

    return issues, notes


def evaluate_nfs(data_text):
    """
    Returns (판단결과: str, 판단근거: str).
    """
    nfs_running = is_nfs_running(data_text)
    nfs_disabled = is_nfs_disabled_marked(data_text)

    export_lines = extract_export_lines(data_text)

    # 1) export 설정이 없는 경우
    if not export_lines:
        if nfs_running and not nfs_disabled:
            return (
                "양호",
                "[확인값] NFS 데몬 동작 중이나 /etc/exports 설정 없음\n"
                "[기준] 접근 호스트 제한 적용 또는 공유 미존재\n"
                "[판단] 공유 항목 없음 → 양호",
            )
        return (
            "양호",
            "[확인값] NFS 서비스 비활성 또는 /etc/exports 설정 없음\n"
            "[기준] NFS 미사용 또는 접근 호스트 제한 적용\n"
            "[판단] 공유 항목 없음 → 양호",
        )

    # 2) export 항목이 있는 경우
    all_issues = []
    all_notes = []
    parsed_summaries = []

    for line in export_lines:
        parsed = parse_export_line(line)
        if not parsed:
            continue
        if parsed["syntax"] == "aix":
            issues, notes = evaluate_aix_entry(parsed)
            parsed_summaries.append(f"  - {parsed['path']} -{parsed['raw_opts']}  (AIX)")
        else:
            issues, notes = evaluate_linux_entry(parsed)
            parsed_summaries.append(f"  - {parsed['path']} {parsed['raw']}  (Linux)")
        all_issues.extend(issues)
        all_notes.extend(notes)

    summary_block = "[/etc/exports 항목]\n" + "\n".join(parsed_summaries)
    notes_block = ("\n[참고]\n" + "\n".join(f"  - {n}" for n in all_notes)) if all_notes else ""

    # 데몬은 안 도는데 설정에 이슈가 있으면 → 양호 (잠재 이슈만 기록)
    if all_issues and nfs_disabled and not nfs_running:
        return (
            "양호",
            f"{summary_block}\n"
            f"[기준] NFS 데몬 미동작 시 export 설정 미적용 (잠재 이슈는 활성화 전 정비 필요)\n"
            f"[판단] 서비스 비활성 → 양호\n"
            f"[잠재 이슈]\n" + "\n".join(f"  - {i}" for i in all_issues)
            + notes_block,
        )

    if all_issues:
        return (
            "취약",
            f"{summary_block}\n"
            f"[기준] 접근 호스트 제한, 광범위 root squash 예외 금지, 와일드카드 RW 금지\n"
            f"[판단] 다음 사유로 취약\n"
            + "\n".join(f"  - {i}" for i in all_issues)
            + notes_block,
        )

    return (
        "양호",
        f"{summary_block}\n"
        f"[기준] 접근 호스트 제한, root squash 적용, 와일드카드 공유 금지\n"
        f"[판단] 모든 export 항목이 호스트 제한 + 적정 권한으로 공유됨 → 양호"
        + notes_block,
    )
