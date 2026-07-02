#!/usr/bin/env python3
"""构建 libraries_categorized.json 中所有库的依赖图谱（含传递依赖）。

数据来源：PyPI JSON API（https://pypi.org/pypi/<name>/json 的 info.requires_dist）。
环境相关的 marker（python_version、sys_platform 等）按运行本脚本时的当前环境求值，
不代表在所有平台/Python 版本下都成立。extras（可选依赖组，如 test/docs）默认不展开，
用 --include-extras 打开。

用法:
    python3 dependency_graph.py
    python3 dependency_graph.py --max-depth 2 --dot dependency_graph.dot
    python3 dependency_graph.py --include-extras --no-cache
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"
CACHE_DIR = Path(__file__).parent / ".cache" / "pypi"
REQUEST_TIMEOUT = 15
MAX_WORKERS = 8
EXTRA_RE = re.compile(r'extra\s*==\s*[\'"]([^\'"]+)[\'"]')


def normalize(name: str) -> str:
    return canonicalize_name(name)


def load_root_libraries(categorized_json: Path) -> dict[str, str]:
    """返回 {规范化包名: 所属分类} 映射。"""
    data = json.loads(categorized_json.read_text(encoding="utf-8"))
    roots: dict[str, str] = {}
    for cat in data.get("categories", []):
        for lib in cat.get("libraries", []):
            roots[normalize(lib["name"])] = cat["category"]
    return roots


def fetch_metadata(name: str, session: requests.Session, use_cache: bool) -> dict | None:
    """抓取 PyPI 包的 JSON 元数据；包不存在（或抓取失败）返回 None。"""
    cache_file = CACHE_DIR / f"{name}.json"
    if use_cache and cache_file.exists():
        text = cache_file.read_text(encoding="utf-8")
        return json.loads(text) if text != "null" else None

    try:
        resp = session.get(PYPI_JSON_URL.format(name=name), timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        print(f"  [警告] 请求 {name} 失败: {exc}", file=sys.stderr)
        return None

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if resp.status_code == 404:
        cache_file.write_text("null", encoding="utf-8")
        return None
    if resp.status_code != 200:
        print(f"  [警告] {name} 返回状态码 {resp.status_code}", file=sys.stderr)
        return None

    data = resp.json()
    cache_file.write_text(json.dumps(data), encoding="utf-8")
    return data


def parse_dependencies(metadata: dict, include_extras: bool) -> list[tuple[str, str, str | None]]:
    """解析 requires_dist，返回 (依赖规范名, 原始声明, 所属 extra 或 None) 列表。"""
    requires_dist = (metadata.get("info") or {}).get("requires_dist") or []
    deps: list[tuple[str, str, str | None]] = []
    for raw in requires_dist:
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            continue

        gated_extra = None
        if req.marker is not None:
            match = EXTRA_RE.search(str(req.marker))
            gated_extra = match.group(1) if match else None

            if gated_extra:
                if not include_extras:
                    continue
            else:
                # 非 extra 的环境 marker（python_version / sys_platform 等），按当前环境求值
                try:
                    if not req.marker.evaluate():
                        continue
                except Exception:
                    pass

        deps.append((normalize(req.name), raw, gated_extra))
    return deps


def build_graph(
    root_names: dict[str, str],
    include_extras: bool,
    max_depth: int | None,
    max_nodes: int,
    use_cache: bool,
) -> tuple[dict[str, dict], list[dict]]:
    session = requests.Session()
    session.headers["User-Agent"] = "dependency-graph-analysis/1.0 (local research script)"

    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    visited: set[str] = set()
    frontier: dict[str, int] = {name: 0 for name in root_names}
    wave = 0

    while frontier:
        if len(visited) >= max_nodes:
            print(f"[提示] 已达节点上限 {max_nodes}，停止继续展开", file=sys.stderr)
            break

        batch = {n: d for n, d in frontier.items() if n not in visited}
        frontier = {}
        if not batch:
            break
        for n in batch:
            visited.add(n)

        wave += 1
        print(f"第 {wave} 轮: 抓取 {len(batch)} 个包...")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = {
                pool.submit(fetch_metadata, n, session, use_cache): (n, d)
                for n, d in batch.items()
            }
            for fut in as_completed(futures):
                name, depth = futures[fut]
                metadata = fut.result()

                node = nodes.setdefault(name, {"name": name})
                node["is_root"] = name in root_names
                node["category"] = root_names.get(name)
                node["resolved"] = metadata is not None
                node["depth"] = depth
                node["version"] = (metadata.get("info") or {}).get("version") if metadata else None

                if metadata is None or (max_depth is not None and depth >= max_depth):
                    continue

                for dep_name, raw, extra in parse_dependencies(metadata, include_extras):
                    edges.append({"from": name, "to": dep_name, "requirement": raw, "extra": extra})
                    if dep_name not in visited and dep_name not in frontier:
                        frontier[dep_name] = depth + 1

        time.sleep(0.05)  # 轻微限速，避免对 PyPI 造成压力

    # 未被实际抓取（达到节点上限而被截断）的边端点，补一个占位节点
    for e in edges:
        for key in ("from", "to"):
            n = e[key]
            if n not in nodes:
                nodes[n] = {
                    "name": n,
                    "is_root": n in root_names,
                    "category": root_names.get(n),
                    "resolved": None,
                    "depth": None,
                    "version": None,
                    "note": "未展开（达到节点上限）",
                }

    return nodes, edges


def export_dot(nodes: dict[str, dict], edges: list[dict], path: Path) -> None:
    lines = ["digraph dependencies {", "  rankdir=LR;", "  node [shape=box, fontsize=10, style=filled];"]
    for n in nodes.values():
        label = n["name"] + (f"\\n{n['version']}" if n.get("version") else "")
        if n.get("is_root"):
            color = "#a6cee3"
        elif n.get("resolved") is False:
            color = "#fb9a99"
        else:
            color = "#f0f0f0"
        lines.append(f'  "{n["name"]}" [label="{label}", fillcolor="{color}"];')
    for e in edges:
        lines.append(f'  "{e["from"]}" -> "{e["to"]}";')
    lines.append("}")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="构建 Python 库依赖图谱（含传递依赖）")
    parser.add_argument("--input", type=Path, default=Path(__file__).parent / "libraries_categorized.json")
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "dependency_graph.json")
    parser.add_argument("--dot", type=Path, default=None, help="额外导出 Graphviz DOT 文件")
    parser.add_argument("--include-extras", action="store_true", help="展开可选 extras 依赖（默认不展开）")
    parser.add_argument("--max-depth", type=int, default=None, help="最大展开深度（默认不限，直到无新依赖）")
    parser.add_argument("--max-nodes", type=int, default=3000, help="节点数量安全上限")
    parser.add_argument("--no-cache", action="store_true", help="忽略本地缓存，强制重新请求 PyPI")
    args = parser.parse_args()

    root_names = load_root_libraries(args.input)
    print(f"根节点（清单库）: {len(root_names)} 个\n")

    nodes, edges = build_graph(
        root_names, args.include_extras, args.max_depth, args.max_nodes, not args.no_cache
    )

    result = {
        "meta": {
            "root_count": len(root_names),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "include_extras": args.include_extras,
            "max_depth": args.max_depth,
        },
        "nodes": sorted(nodes.values(), key=lambda n: (not n["is_root"], n["name"])),
        "edges": edges,
    }
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n图谱已写入: {args.output}")

    if args.dot:
        export_dot(nodes, edges, args.dot)
        print(f"DOT 文件已写入: {args.dot}（可用 `dot -Tsvg {args.dot} -o graph.svg` 渲染，需安装 graphviz）")

    unresolved = sorted(n["name"] for n in nodes.values() if n.get("resolved") is False)
    in_degree: dict[str, int] = {}
    for e in edges:
        in_degree[e["to"]] = in_degree.get(e["to"], 0) + 1
    top = sorted(in_degree.items(), key=lambda kv: -kv[1])[:15]

    print(f"\n节点总数: {len(nodes)}，边总数: {len(edges)}")
    print(f"未在 PyPI 找到的包（内部/私有包或名称不一致）: {unresolved or '无'}")
    print("\n被依赖次数最多的库（Top 15，含传递依赖）:")
    for name, count in top:
        print(f"  {name}: {count}")


if __name__ == "__main__":
    main()
