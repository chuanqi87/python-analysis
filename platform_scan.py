#!/usr/bin/env python3
"""检测 libraries_categorized.json / dependency_graph.json 中各库的平台专属特征。

用于评估「哪些库需要做鸿蒙化适配」时的分诊依据。检测分两层：

一、元数据层（零网络成本，直接读 .cache/pypi/*.json 里已缓存的 PyPI JSON）
    1. wheel 文件名中的平台 tag（PEP 425）：win32/win_amd64、manylinux*/linux_*/musllinux*、
       macosx_*/universal2。只看"最新版本"：若同一版本下出现 >=2 个不同 OS 家族的平台 tag，
       说明该库发布了按平台分别编译的原生扩展（等价于"依赖 .so，需要每个平台编译"）；只出现
       单一 OS 家族，说明该库只为该 OS 提供预编译产物。历史版本的 wheel 家族仅作为参考字段
       记录，不参与判定——不少库（如 mistune、lifelines）在 cp27/cp33 时代发过平台限定 wheel，
       现在早已是纯 Python，把全部历史纳入判定会把"多年前的旧状态"误判成"现在仍是原生库"。
    2. PyPI classifiers 里的 `Operating System :: ...`：明确声明仅支持的操作系统。
    3. `requires_dist` 原始声明里的环境 marker（sys_platform / platform_system / os_name /
       platform_machine）：依赖关系本身按平台分支（如 pywin32 只在 win32 装）。
    4. 包名启发式：包含 win32/pywin/windows/darwin/posix/xlib 等 token。

    局限：元数据层只能测出"发布了平台限定的编译产物"或"声明了平台限定"，测不出"wheel 显示
    纯 Python，但运行时用 ctypes 动态加载系统原生库"这类情况（例如 PyOpenGL：无 classifier、
    只发 py3-none-any wheel，但内部用 ctypes 加载 opengl32.dll / libGL.so）。这类情况必须
    结合源码层扫描才能发现。

二、源码层（需下载 sdist 解压扫描，默认开启，可用 --no-deep 关闭）
    1. 打包了原生二进制：*.so / *.pyd / *.dylib / *.dll。
    2. 构建配置里的原生扩展痕迹：setup.py/setup.cfg/pyproject.toml 中的 ext_modules=、
       Extension(、cythonize(、setuptools_rust、maturin、pybind11、cffi；以及 Cargo.toml /
       CMakeLists.txt / *.pyx 源文件的存在。
    3. 代码里的操作系统判断分支：sys.platform、platform.system()、os.name、
       sysconfig.get_platform()、platform.uname()。
    4. 代码里通过 ctypes 动态加载系统原生库：ctypes.CDLL/WinDLL/windll、cdll.LoadLibrary、
       find_library(。

    这一层基于正则匹配源码文本，不是 100% 完备（测不出安装时脚本临时下载平台二进制这类更隐蔽
    的模式），产出应视为高置信度的分诊清单，被标记的库仍建议做一次实际编译/导入验证。

用法:
    python3 platform_scan.py                        # 全量：依赖图谱 320 个节点，元数据层+源码层
    python3 platform_scan.py --root-only             # 只分析 89 个根库
    python3 platform_scan.py --no-deep               # 只做元数据层（快，但会漏检 ctypes 等运行时绑定）
    python3 platform_scan.py --limit 10              # 调试：只跑前 10 个节点
    python3 platform_scan.py --deep-max-size-mb 200  # 调整 sdist 下载大小上限
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).parent
PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
PYPI_CACHE_DIR = ROOT / ".cache" / "pypi"
SDIST_CACHE_DIR = ROOT / ".cache" / "sdist"
REQUEST_TIMEOUT = 20
DEFAULT_WORKERS = 6
DEFAULT_MAX_SDIST_MB = 120
MAX_FILE_READ_BYTES = 2_000_000  # 单文件超过此大小不读内容（多为数据文件而非代码）
MAX_HITS_PER_PATTERN = 3
MAX_FILES_PER_PACKAGE = 5000

# ---------------- 元数据层规则 ----------------

OS_FAMILY_PATTERNS = [
    ("win", re.compile(r"win32|win_amd64|win_arm64|^win", re.I)),
    ("linux", re.compile(r"linux|manylinux|musllinux", re.I)),
    ("macos", re.compile(r"macosx|universal2", re.I)),
]
NAME_HEURISTIC_RE = re.compile(
    r"(win32|pywin|-win\b|^win-|windows|applescript|darwin|\bposix\b|x11|xlib)", re.I
)
PLATFORM_MARKER_RE = re.compile(r"sys_platform|platform_system|os_name|platform_machine")
CLASSIFIER_FAMILY_PATTERNS = [
    ("win", re.compile(r"Microsoft|Windows", re.I)),
    ("macos", re.compile(r"MacOS|Darwin|iOS", re.I)),
    ("linux", re.compile(r"POSIX|Linux|Unix", re.I)),
]

# ---------------- 源码层规则 ----------------

CODE_PLATFORM_CHECK_PATTERNS = {
    "sys.platform": re.compile(r"\bsys\.platform\b"),
    "platform.system()": re.compile(r"\bplatform\.system\s*\("),
    "os.name": re.compile(r"\bos\.name\b\s*(==|!=|in)"),
    "sysconfig.get_platform()": re.compile(r"\bsysconfig\.get_platform\s*\("),
    "platform.uname()": re.compile(r"\bplatform\.uname\s*\("),
}
CODE_CTYPES_LOAD_PATTERNS = {
    "ctypes.WinDLL": re.compile(r"\bctypes\.WinDLL\b"),
    "ctypes.windll": re.compile(r"\bctypes\.windll\b"),
    "ctypes.CDLL": re.compile(r"\bctypes\.CDLL\b"),
    "cdll.LoadLibrary": re.compile(r"\bcdll\.LoadLibrary\b"),
    "find_library(": re.compile(r"\bfind_library\s*\("),
}
BUILD_SYSTEM_PATTERNS = {
    "ext_modules": re.compile(r"\bext_modules\s*="),
    "Extension(": re.compile(r"\bExtension\s*\("),
    "cythonize(": re.compile(r"\bcythonize\s*\("),
    "setuptools_rust": re.compile(r"setuptools[-_]rust"),
    "maturin": re.compile(r"\bmaturin\b"),
    "pybind11": re.compile(r"\bpybind11\b"),
    "cffi": re.compile(r"\bcffi\b"),
}
BINARY_EXTS = {".so", ".pyd", ".dylib", ".dll"}
NATIVE_BUILD_FILES = {"cargo.toml": "Rust(Cargo.toml)", "cmakelists.txt": "CMake"}
CYTHON_SOURCE_EXTS = {".pyx", ".pxd"}
SOURCE_TEXT_EXTS = {".py", ".pyx", ".pxd", ".pxi", ".toml", ".cfg", ".in"}

VERDICT_LABELS = {
    "native_compiled": "含原生编译产物（发布的 wheel 或包内确有平台专属二进制，需按目标平台/架构重新构建）",
    "os_specific_api": "纯 Python 但绑定特定 OS API（需评估鸿蒙上有无替代方案）",
    "optional_native_build": "标准发行版为纯 Python，源码含可选/需手动开启的原生加速构建路径（优先级低于 native_compiled，仍建议关注）",
    "platform_branching": "源码含操作系统分支判断（通常需要补充适配分支）",
    "cross_platform": "未发现平台专属迹象",
    "unresolved": "PyPI 未解析到（内部/私有包，需人工确认）",
    "error": "分析过程出错",
}


def normalize(name: str) -> str:
    return canonicalize_name(name)


def _version_sort_key(v: str):
    try:
        return Version(v)
    except InvalidVersion:
        return Version("0")


# ==================== 元数据层 ====================


def load_pypi_metadata(name: str, session: requests.Session, use_cache: bool) -> dict | None:
    cache_file = PYPI_CACHE_DIR / f"{name}.json"
    if use_cache and cache_file.exists():
        text = cache_file.read_text(encoding="utf-8")
        return json.loads(text) if text != "null" else None
    try:
        resp = session.get(PYPI_JSON_URL.format(name=name), timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        print(f"  [警告] 请求 {name} 失败: {exc}", file=sys.stderr)
        return None
    PYPI_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if resp.status_code == 404:
        cache_file.write_text("null", encoding="utf-8")
        return None
    if resp.status_code != 200:
        print(f"  [警告] {name} 返回状态码 {resp.status_code}", file=sys.stderr)
        return None
    data = resp.json()
    cache_file.write_text(json.dumps(data), encoding="utf-8")
    return data


def wheel_platform_families(filename: str) -> set[str]:
    if not filename.endswith(".whl"):
        return set()
    parts = filename[: -len(".whl")].split("-")
    platform_tag = parts[-1] if parts else ""
    if platform_tag == "any":
        return {"any"}
    families = {family for family, pattern in OS_FAMILY_PATTERNS if pattern.search(platform_tag)}
    return families or {"other"}


def os_classifiers(info: dict) -> list[str]:
    result = []
    for c in info.get("classifiers") or []:
        if c.startswith("Operating System"):
            result.append(c[len("Operating System") :].lstrip(" :"))
    return result


def classifier_os_families(classifiers: list[str]) -> set[str]:
    """把 classifier 文本映射到 win/macos/linux 三大家族，用于判断是"声明支持全部主流平台"
    （如同时列出 Windows+MacOS+POSIX，等同于全平台支持，不算限制信号）还是"只声明部分平台"
    （真正的限制信号，如只列 Windows）。"""
    families: set[str] = set()
    for c in classifiers:
        for family, pattern in CLASSIFIER_FAMILY_PATTERNS:
            if pattern.search(c):
                families.add(family)
    return families


def tier1_signals(name: str, data: dict) -> dict:
    info = data.get("info") or {}
    classifiers = os_classifiers(info)
    os_independent_declared = any("Independent" in c for c in classifiers)
    specific_os_classifiers = [c for c in classifiers if "Independent" not in c]

    latest_wheel_families: set[str] = set()
    latest_has_sdist = False
    for u in data.get("urls") or []:
        fn = u.get("filename", "")
        if fn.endswith(".whl"):
            latest_wheel_families |= wheel_platform_families(fn)
        elif fn.endswith((".tar.gz", ".zip", ".tar.bz2")):
            latest_has_sdist = True

    history_wheel_families = set(latest_wheel_families)
    for files in (data.get("releases") or {}).values():
        for f in files:
            fn = f.get("filename", "")
            if fn.endswith(".whl"):
                history_wheel_families |= wheel_platform_families(fn)

    requires_dist = info.get("requires_dist") or []
    platform_markers = [r for r in requires_dist if PLATFORM_MARKER_RE.search(r)]

    return {
        "os_classifiers": specific_os_classifiers,
        "os_classifier_families": sorted(classifier_os_families(specific_os_classifiers)),
        "os_independent_declared": os_independent_declared,
        "latest_wheel_platforms": sorted(latest_wheel_families - {"any"}),
        "latest_only_sdist": latest_has_sdist and not latest_wheel_families,
        "history_wheel_platforms": sorted(history_wheel_families - {"any"}),
        "requires_dist_platform_markers": platform_markers,
        "name_heuristic_hit": bool(NAME_HEURISTIC_RE.search(name)),
    }


def find_source_archive_url(data: dict) -> tuple[str, str, str] | None:
    """返回最新可下载的源码归档 (version, url, kind)，kind 为 "sdist" 或 "wheel"。

    优先用 sdist（含 setup.py/pyproject.toml，构建系统证据最完整）；若该库压根不发布 sdist
    （只发 wheel，如 tjc-common、wisepy2），回退到 wheel —— wheel 本质也是 zip 包，一样能读到
    里面的 .py 源码用于 sys.platform/ctypes 扫描，只是拿不到 setup.py 里的构建系统证据。
    最新版本都没有时，回退到较早版本。找不到任何可下载文件时返回 None。
    """

    def sdist_in(files):
        for f in files:
            if f.get("packagetype") == "sdist":
                return f
        return None

    def any_wheel_in(files):
        wheels = [f for f in files if f.get("filename", "").endswith(".whl")]
        if not wheels:
            return None
        for f in wheels:
            if f["filename"].endswith(("-any.whl", "-none-any.whl")):
                return f
        return wheels[0]

    info = data.get("info") or {}
    latest_version = info.get("version")
    latest_urls = data.get("urls") or []
    f = sdist_in(latest_urls)
    if f:
        return latest_version, f["url"], "sdist"
    f = any_wheel_in(latest_urls)
    if f:
        return latest_version, f["url"], "wheel"

    releases = data.get("releases") or {}
    for version in sorted(releases.keys(), key=_version_sort_key, reverse=True):
        f = sdist_in(releases[version])
        if f:
            return version, f["url"], "sdist"
        f = any_wheel_in(releases[version])
        if f:
            return version, f["url"], "wheel"
    return None


# ==================== 源码层 ====================


class ArchiveMember:
    __slots__ = ("name", "size", "_read")

    def __init__(self, name, size, read):
        self.name = name
        self.size = size
        self._read = read

    def read(self) -> bytes:
        return self._read()


def iter_archive_members(path: Path):
    lower = path.name.lower()
    if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar")):
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue

                def _read(tf=tf, member=member):
                    f = tf.extractfile(member)
                    return f.read() if f else b""

                yield ArchiveMember(member.name, member.size, _read)
    elif lower.endswith((".zip", ".whl")):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                def _read(zf=zf, info=info):
                    return zf.read(info)

                yield ArchiveMember(info.filename, info.file_size, _read)
    else:
        return


def _archive_suffix(url: str) -> str:
    for suf in (".tar.gz", ".tgz", ".tar.bz2", ".whl", ".zip"):
        if url.endswith(suf):
            return suf
    return ".bin"


def download_archive(
    name: str, version: str, url: str, session: requests.Session, max_size_bytes: int
) -> tuple[str, object]:
    suffix = _archive_suffix(url)
    cache_file = SDIST_CACHE_DIR / f"{normalize(name)}-{version}{suffix}"
    if cache_file.exists():
        return "ok", cache_file
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT * 3, stream=True)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return "error", str(exc)

    content_length = int(resp.headers.get("Content-Length") or 0)
    if content_length and content_length > max_size_bytes:
        resp.close()
        return "too_large", content_length

    SDIST_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    tmp_file = cache_file.with_suffix(cache_file.suffix + ".part")
    total = 0
    try:
        with open(tmp_file, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=1 << 16):
                total += len(chunk)
                if total > max_size_bytes:
                    resp.close()
                    tmp_file.unlink(missing_ok=True)
                    return "too_large", total
                fh.write(chunk)
    except requests.RequestException as exc:
        tmp_file.unlink(missing_ok=True)
        return "error", str(exc)

    tmp_file.rename(cache_file)
    return "ok", cache_file


def tier2_signals(archive_path: Path) -> dict:
    binary_files = []
    native_build_files = []
    cython_files = []
    build_system_hits: dict[str, list[str]] = {}
    platform_check_hits: dict[str, list[str]] = {}
    ctypes_load_hits: dict[str, list[str]] = {}
    file_count = 0
    truncated = False
    read_error = None

    try:
        for member in iter_archive_members(archive_path):
            file_count += 1
            if file_count > MAX_FILES_PER_PACKAGE:
                truncated = True
                break

            lower_name = member.name.lower()
            base = Path(lower_name).name
            ext = Path(lower_name).suffix

            if ext in BINARY_EXTS:
                binary_files.append(member.name)
                continue
            if base in NATIVE_BUILD_FILES:
                native_build_files.append(NATIVE_BUILD_FILES[base])
                continue
            if ext in CYTHON_SOURCE_EXTS:
                cython_files.append(member.name)

            if ext not in SOURCE_TEXT_EXTS or member.size > MAX_FILE_READ_BYTES:
                continue

            try:
                content = member.read().decode("utf-8", errors="ignore")
            except Exception:
                continue

            pattern_groups = [
                (CODE_PLATFORM_CHECK_PATTERNS, platform_check_hits),
                (CODE_CTYPES_LOAD_PATTERNS, ctypes_load_hits),
            ]
            if base in ("setup.py", "setup.cfg", "pyproject.toml"):
                pattern_groups.append((BUILD_SYSTEM_PATTERNS, build_system_hits))

            for patterns, bucket in pattern_groups:
                for label, regex in patterns.items():
                    if regex.search(content):
                        hits = bucket.setdefault(label, [])
                        if len(hits) < MAX_HITS_PER_PATTERN:
                            hits.append(member.name)
    except Exception as exc:  # 解压/读取异常不应中断整体批量分析
        read_error = str(exc)

    return {
        "scanned_file_count": file_count,
        "truncated": truncated,
        "bundled_binary_files": binary_files[:20],
        "bundled_binary_file_count": len(binary_files),
        "native_build_files": sorted(set(native_build_files)),
        "cython_source_files": cython_files[:10],
        "cython_source_file_count": len(cython_files),
        "build_system_hits": build_system_hits,
        "platform_check_hits": platform_check_hits,
        "ctypes_native_load_hits": ctypes_load_hits,
        "read_error": read_error,
    }


# ==================== 综合判定 ====================


def classify(tier1: dict, tier2: dict | None) -> dict:
    reasons = []
    flags = set()

    # 只信任"最新版本"发布的 wheel 平台标签。历史版本（history_wheel_platforms）不参与判定：
    # 早期 Python 生态里很多现已是纯 Python 的库（如 mistune、lifelines）在 cp27/cp33 时代发布过
    # 平台限定 wheel，若把全部历史版本纳入判定会把"多年前的旧状态"误判成"当前仍是原生库"。
    wheel_platforms = set(tier1["latest_wheel_platforms"])
    has_published_native_wheel = bool(wheel_platforms)
    if len(wheel_platforms) >= 2:
        flags.add("native_compiled")
        reasons.append(f"最新版本发布了跨多个操作系统家族的编译 wheel: {sorted(wheel_platforms)}")
    elif len(wheel_platforms) == 1:
        flags.add("native_compiled")
        reasons.append(f"最新版本仅为单一操作系统发布编译 wheel: {sorted(wheel_platforms)}")

    has_bundled_binary = False
    if tier2:
        has_bundled_binary = bool(tier2["bundled_binary_file_count"])
        if has_bundled_binary:
            flags.add("native_compiled")
            reasons.append(
                f"源码包内打包了原生二进制文件（{tier2['bundled_binary_file_count']} 个），"
                f"如 {tier2['bundled_binary_files'][:3]}"
            )

        build_hints = list(tier2["build_system_hits"].keys())
        if tier2["cython_source_file_count"]:
            build_hints.append("Cython(.pyx)")
        build_hints += tier2["native_build_files"]
        if build_hints:
            if has_published_native_wheel or has_bundled_binary:
                # 已经有更直接的证据（实际发布的平台 wheel / 包内二进制），构建痕迹只作为佐证，不重复升级判定
                reasons.append(f"构建配置中存在原生扩展构建痕迹（佐证）: {build_hints}")
            elif tier1["latest_only_sdist"]:
                # 最新版本完全没有发布 wheel（只有 sdist），且构建配置里确有原生扩展痕迹：
                # 意味着用户每次安装都必须在本地现场编译，比"发了预编译 wheel"风险更高，不能算 optional
                flags.add("native_compiled")
                reasons.append(
                    f"最新版本未发布任何 wheel（仅 sdist），且构建配置中存在原生扩展痕迹，安装时需现场编译: {build_hints}"
                )
            else:
                # 例如 openpyxl：setup.py 里有可选 Cython 加速路径，但需手动传 --with-cython 才触发，
                # PyPI 发布的 wheel 全部是纯 Python，不应等同于"默认就要装原生二进制"的 numexpr/PyOpenGL
                flags.add("optional_native_build")
                reasons.append(
                    f"构建配置中存在原生扩展构建痕迹，但发布的 wheel 均为纯 Python（可能是可选/需手动开启的加速路径）: {build_hints}"
                )

    classifier_families = set(tier1["os_classifier_families"])
    if classifier_families and len(classifier_families) < 3 and not tier1["os_independent_declared"]:
        # 只声明了部分 OS 家族才算限制信号；同时列出 win+macos+linux 等价于"全平台支持"，不算限制
        flags.add("os_specific_api")
        reasons.append(f"PyPI classifier 声明仅支持部分操作系统: {tier1['os_classifiers']}")
    if tier1["requires_dist_platform_markers"]:
        flags.add("os_specific_api")
        reasons.append(f"依赖声明按平台分支: {tier1['requires_dist_platform_markers']}")
    if tier1["name_heuristic_hit"]:
        flags.add("os_specific_api")
        reasons.append("包名包含平台相关关键字")
    if tier2 and tier2["ctypes_native_load_hits"]:
        flags.add("os_specific_api")
        reasons.append(f"源码中通过 ctypes 动态加载系统原生库: {list(tier2['ctypes_native_load_hits'].keys())}")

    if tier2 and tier2["platform_check_hits"]:
        flags.add("platform_branching")
        reasons.append(f"源码中存在操作系统判断分支: {list(tier2['platform_check_hits'].keys())}")

    if not flags:
        verdict = "cross_platform"
    elif "native_compiled" in flags:
        verdict = "native_compiled"
    elif "os_specific_api" in flags:
        verdict = "os_specific_api"
    elif "optional_native_build" in flags:
        verdict = "optional_native_build"
    else:
        verdict = "platform_branching"

    return {"verdict": verdict, "flags": sorted(flags), "reasons": reasons}


# ==================== 单包分析 & 批量编排 ====================


def analyze_one(name: str, category: str | None, is_root: bool, session: requests.Session, args) -> dict:
    data = load_pypi_metadata(name, session, use_cache=not args.no_cache)
    if data is None:
        return {
            "name": name,
            "category": category,
            "is_root": is_root,
            "resolved": False,
            "verdict": "unresolved",
            "flags": [],
            "reasons": ["PyPI 上未找到该包（内部/私有包或名称不一致），无法分析，需人工确认"],
        }

    tier1 = tier1_signals(name, data)
    tier2 = None
    deep_status = "not_requested"

    if args.deep:
        archive_info = find_source_archive_url(data)
        if archive_info is None:
            deep_status = "no_archive_available"
        else:
            version, url, kind = archive_info
            status, payload = download_archive(
                name, version, url, session, int(args.deep_max_size_mb * 1024 * 1024)
            )
            if status == "ok":
                tier2 = tier2_signals(payload)
                # wheel 里没有 setup.py/pyproject.toml，扫不到构建系统证据，只标注来源供复核参考
                deep_status = "ok" if kind == "sdist" else "ok_wheel_fallback"
            elif status == "too_large":
                deep_status = f"too_large({payload / (1024 * 1024):.1f}MB > {args.deep_max_size_mb}MB)"
            else:
                deep_status = f"download_error({payload})"

    verdict_info = classify(tier1, tier2)
    if args.deep and tier2 is None:
        verdict_info["reasons"].append(f"[注意] 未完成源码级扫描（{deep_status}），结论可能不完整，建议人工复核")

    return {
        "name": name,
        "category": category,
        "is_root": is_root,
        "resolved": True,
        "latest_version": (data.get("info") or {}).get("version"),
        "tier1": tier1,
        "tier2": tier2,
        "deep_status": deep_status,
        **verdict_info,
    }


def load_root_categories(categorized_json: Path) -> dict[str, str]:
    data = json.loads(categorized_json.read_text(encoding="utf-8"))
    roots: dict[str, str] = {}
    for cat in data.get("categories", []):
        for lib in cat["libraries"]:
            roots[normalize(lib["name"])] = cat["category"]
    return roots


def print_summary(results: list[dict]) -> None:
    counts = Counter(r["verdict"] for r in results)
    print("\n===== 判定结果汇总（全部节点） =====")
    for verdict, label in VERDICT_LABELS.items():
        if counts.get(verdict):
            print(f"  [{verdict}] {label}: {counts[verdict]}")

    print("\n===== 根库中需要重点关注的条目（按类别） =====")
    flagged_roots = [
        r
        for r in results
        if r.get("is_root")
        and r["verdict"] in ("native_compiled", "os_specific_api", "optional_native_build", "platform_branching")
    ]
    by_category: dict[str, list[dict]] = {}
    for r in flagged_roots:
        by_category.setdefault(r.get("category") or "未分类", []).append(r)
    for category, items in by_category.items():
        print(f"\n  ▸ {category}")
        for r in items:
            print(f"    [{r['verdict']}] {r['name']}")
            for reason in r.get("reasons", [])[:2]:
                print(f"        - {reason}")

    unresolved_roots = [r["name"] for r in results if r.get("is_root") and r["verdict"] == "unresolved"]
    if unresolved_roots:
        print(f"\n  [unresolved] 根库中未在 PyPI 解析到的包（需人工确认）: {unresolved_roots}")


def main() -> None:
    parser = argparse.ArgumentParser(description="检测库的平台专属特征，用于评估鸿蒙化适配范围")
    parser.add_argument("--graph", type=Path, default=ROOT / "dependency_graph.json")
    parser.add_argument("--categorized", type=Path, default=ROOT / "libraries_categorized.json")
    parser.add_argument(
        "--root-only", action="store_true", help="只分析 libraries_categorized.json 中的根库（默认含依赖图谱全部传递依赖）"
    )
    parser.add_argument("--no-deep", action="store_true", help="跳过源码层扫描，只做元数据层分析")
    parser.add_argument("--deep-max-size-mb", type=float, default=DEFAULT_MAX_SDIST_MB, help="单个 sdist 下载大小上限（MB）")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--no-cache", action="store_true", help="忽略 PyPI 元数据缓存，强制重新请求")
    parser.add_argument("--output", type=Path, default=ROOT / "platform_analysis.json")
    parser.add_argument("--limit", type=int, default=None, help="仅分析前 N 个节点（调试用）")
    args = parser.parse_args()
    args.deep = not args.no_deep

    root_categories = load_root_categories(args.categorized)

    if args.root_only:
        targets = [(name, cat, True) for name, cat in root_categories.items()]
    else:
        graph = json.loads(args.graph.read_text(encoding="utf-8"))
        targets = [
            (node["name"], root_categories.get(node["name"]), node["name"] in root_categories)
            for node in graph["nodes"]
        ]

    if args.limit:
        targets = targets[: args.limit]

    print(f"待分析节点数: {len(targets)}（源码层扫描: {'开启' if args.deep else '关闭'}）\n")

    session = requests.Session()
    session.headers["User-Agent"] = "platform-scan/1.0 (local research script)"

    results = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(analyze_one, name, cat, is_root, session, args): name for name, cat, is_root in targets
        }
        done = 0
        for fut in as_completed(futures):
            name = futures[fut]
            done += 1
            try:
                result = fut.result()
            except Exception as exc:
                result = {
                    "name": name,
                    "resolved": False,
                    "verdict": "error",
                    "flags": [],
                    "reasons": [f"分析异常: {exc}"],
                }
            results.append(result)
            if done % 20 == 0 or done == len(targets):
                print(f"  进度 {done}/{len(targets)}")

    results.sort(key=lambda r: (not r.get("is_root", False), r["name"]))

    report = {
        "meta": {
            "total": len(results),
            "deep_scan": args.deep,
            "root_only": args.root_only,
            "verdict_labels": VERDICT_LABELS,
        },
        "results": results,
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n完整报告已写入: {args.output}")

    print_summary(results)


if __name__ == "__main__":
    main()
