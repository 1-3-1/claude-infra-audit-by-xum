"""Unix OS 점검 evaluator 모듈 모음.

파일명에 하이픈(`U-40_NFS.py`)이 들어 있어 Python 의 일반 `import` 가 불가하므로,
이 `__init__.py` 가 `importlib` 로 로드해 깔끔한 이름으로 재노출한다.

호출자(generate_unix.py 등) 사용 예:
    from targets.unix.evaluators import evaluate_nfs, detect_mail_daemon_status, get_na_result

각 evaluator 추가 시 아래 _MODULES 에 한 줄 추가하고, 외부 노출 함수를 등록하면 된다.
"""
import importlib

# ── evaluator 모듈 경로 매핑 (코드번호 prefix 포함 파일명) ──
_MODULES = {
    "nfs":  "targets.unix.evaluators.U-40_NFS",
    "mail": "targets.unix.evaluators.U-45-48_Mail",
}

_loaded = {name: importlib.import_module(path) for name, path in _MODULES.items()}

# ── 외부에 노출할 함수 ──
evaluate_nfs              = _loaded["nfs"].evaluate_nfs
detect_mail_daemon_status = _loaded["mail"].detect_mail_daemon_status
get_na_result             = _loaded["mail"].get_na_result

__all__ = [
    "evaluate_nfs",
    "detect_mail_daemon_status",
    "get_na_result",
]
