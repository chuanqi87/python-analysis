#!/usr/bin/env python3
"""
汇总目标库(platform_analysis.json)在两个 HarmonyOS Python 数据源中的适配状态:
  - support_list: gitcode.com/OpenHarmonyPCDeveloper/Python_Package_For_HarmonyOS 的 support_list.md 静态清单
  - cnb_registry: cnb.cool/OpenHarmonyPCDeveloper/pypi 实时 PyPI 制品仓库(权威,含真实可安装的鸿蒙 wheel)

用法:
  python3 harmony_status_merge.py [--cnb-json cnb_package_versions.json]

cnb_registry 数据来自 JS 渲染的 SPA,无法用 requests/urllib 直接抓取,需要先用具备浏览器渲染
能力的工具(如 firecrawl interact,对 https://cnb.cool/OpenHarmonyPCDeveloper/pypi 反复滚动到底部
直至 a[href*="/-/registries/"] 数量不再增长)导出 {package_name: [version, ...]} 格式的 JSON,
再通过 --cnb-json 传入。若省略该参数,则仅使用 support_list 数据源。
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent
PLATFORM_ANALYSIS = ROOT / "platform_analysis.json"
OUTPUT = ROOT / "harmony_adaptation_status.json"

SUPPORT_LIST_URL = "https://raw.gitcode.com/OpenHarmonyPCDeveloper/Python_Package_For_HarmonyOS/raw/main/support_list.md"

SOURCE_INFO = {
    "support_list": "https://gitcode.com/OpenHarmonyPCDeveloper/Python_Package_For_HarmonyOS/blob/main/support_list.md（静态清单，更新较慢）",
    "cnb_registry": "https://cnb.cool/OpenHarmonyPCDeveloper/pypi（实时 PyPI 制品仓库，权威来源）",
}


def norm(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def fetch_support_list():
    with urlopen(SUPPORT_LIST_URL, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    versions = defaultdict(list)
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("|--") or "PyPI名" in line:
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) < 2 or not parts[0]:
            continue
        pkg, ver = parts[0], parts[1]
        versions[norm(pkg)].append(ver or "(无版本号)")
    return versions


def load_cnb_registry(path):
    if path is None:
        return defaultdict(list)
    raw = json.loads(Path(path).read_text())
    versions = defaultdict(list)
    for pkg, vers in raw.items():
        versions[norm(pkg)].extend(vers)
    return versions


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cnb-json", help="cnb.cool 注册表 {包名: [版本,...]} JSON 文件路径")
    args = parser.parse_args()

    targets = json.loads(PLATFORM_ANALYSIS.read_text())["results"]
    support_versions = fetch_support_list()
    cnb_versions = load_cnb_registry(args.cnb_json)

    results = []
    for t in targets:
        n = norm(t["name"])
        sources = []
        versions_by_source = {}
        if n in support_versions:
            sources.append("support_list")
            versions_by_source["support_list"] = support_versions[n]
        if n in cnb_versions:
            sources.append("cnb_registry")
            versions_by_source["cnb_registry"] = cnb_versions[n]

        results.append({
            "name": t["name"],
            "category": t.get("category") or "未分类(依赖库)",
            "verdict": t["verdict"],
            "harmony_adapted": bool(sources),
            "sources": sources,
            "versions_by_source": versions_by_source,
        })

    adapted = sum(1 for r in results if r["harmony_adapted"])
    only_support = sum(1 for r in results if r["sources"] == ["support_list"])
    only_cnb = sum(1 for r in results if r["sources"] == ["cnb_registry"])
    both = sum(1 for r in results if len(r["sources"]) == 2)

    output = {
        "sources": SOURCE_INFO,
        "total": len(results),
        "adapted_count": adapted,
        "not_adapted_count": len(results) - adapted,
        "only_support_list_count": only_support,
        "only_cnb_registry_count": only_cnb,
        "both_sources_count": both,
        "results": results,
    }
    OUTPUT.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"total={len(results)} adapted={adapted} not_adapted={len(results)-adapted} "
          f"only_support_list={only_support} only_cnb_registry={only_cnb} both={both}", file=sys.stderr)


if __name__ == "__main__":
    main()
