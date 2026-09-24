"""单包许可证替换预演（只读）。

在一条 **已保存审计** 的结果上，仅替换指定单个包节点的许可证为内置矩阵中的
某个候选 SPDX 许可证，依赖图（节点与边）保持原样，复用
``analyzer._build_result`` 沿原依赖图重算全部传递兼容判定与最短冲突路径。

原结果（base）与预演结果（rehearsed）的冲突/告警按
``(ancestor, node)`` 配对，输出：

* ``added``   —— 仅预演结果存在的冲突/告警（新增）；
* ``removed`` —— 仅原结果存在的冲突/告警（消失）；
* ``changed`` —— 双方都存在但严重程度/判定状态/许可证/最短路径/理由变化；

每条配对都携带双方各自的冲突对象（含最短依赖路径 ``path``），
并标注该配对相对被替换节点的角色：``as_ancestor``（被替换节点是祖先）、
``as_dependency``（被替换节点是被依赖方）或 ``unrelated``（同一图上
其他祖先/后代组合因最短路径变化而间接受影响）。

预演是纯内存只读计算：不创建审计、不改动任何复核标记；
原生 manifest 与 CycloneDX 审计结果结构一致，均可直接预演。
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Tuple

from . import analyzer, licenses as lic

KIND = "single-package-license-swap-rehearsal"

DIRECTION = "依赖边方向：使用方 -> 被依赖方；仅替换单个节点许可证，沿原依赖图重算。"

ROLE_AS_ANCESTOR = "as_ancestor"      # 被替换节点在该冲突中是祖先（许可证约束的施加方）
ROLE_AS_DEPENDENCY = "as_dependency"  # 被替换节点在该冲突中是被依赖方
ROLE_UNRELATED = "unrelated"          # 冲突双方均非被替换节点（仅最短路径可能间接变化）

ROLE_LABELS: Dict[str, str] = {
    ROLE_AS_ANCESTOR: "被替换包作为祖先（约束施加方）",
    ROLE_AS_DEPENDENCY: "被替换包作为被依赖方",
    ROLE_UNRELATED: "其他祖先/被依赖方（路径间接变化）",
}

ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"

FIELD_LABELS: Dict[str, str] = {
    "severity": "严重程度（硬冲突/告警）",
    "status": "兼容判定状态",
    "ancestor_license": "祖先节点许可证",
    "node_license": "被依赖节点许可证",
    "path": "最短依赖路径",
    "reason": "判定理由",
}


# --- 入参解析与校验 -----------------------------------------------------------


def resolve_package(result: Dict[str, Any], package_ref: str) -> str:
    """把网页/API 传入的包引用解析为审计中的节点 id。

    优先精确匹配 ``name@version``（大小写不敏感）；只给包名时，
    唯一匹配则解析，零个/多个匹配都抛出 ``ValueError``（API 层转为 422）。
    """
    ref = str(package_ref or "").strip()
    if not ref:
        raise ValueError("请指定要替换许可证的包（name 或 name@version）。")
    nodes = result.get("nodes", []) or []
    by_id = {str(n.get("id")): n for n in nodes}
    if ref in by_id:
        return ref
    lower = ref.lower()
    exact = [nid for nid in by_id if nid.lower() == lower]
    if len(exact) == 1:
        return exact[0]
    # 只给包名（不带 @version）时按名字唯一匹配
    name_matches = [str(n.get("id")) for n in nodes if str(n.get("name", "")).lower() == lower]
    if len(name_matches) == 1:
        return name_matches[0]
    if name_matches:
        raise ValueError(
            "包名 %r 匹配到多个版本：%s，请用 name@version 消歧后重试。"
            % (ref, "、".join(sorted(name_matches)))
        )
    if exact:  # 理论上不会到达（小写重复 id），兜底
        raise ValueError("包 %r 匹配到多个节点：%s。" % (ref, "、".join(sorted(exact))))
    raise ValueError(
        "审计中不存在包：%s。许可证替换预演只能选择该审计中已存在的包节点。" % ref
    )


def resolve_candidate_license(candidate: str) -> str:
    """校验候选许可证在内置矩阵中，返回其规范 SPDX token。

    接受规范标识（``Apache-2.0``）与常见别名（``apache 2.0``、``GPLv3``）；
    无法识别（unknown）一律拒绝并抛出 ``ValueError``（API 层转为 422）。
    """
    text = str(candidate or "").strip()
    if not text:
        raise ValueError("请指定候选 SPDX 许可证（内置矩阵中的许可证标识）。")
    display, token, known = lic.normalize_license(text)
    if not known:
        supported = "、".join(lic.CATEGORIES.keys())
        raise ValueError(
            "候选许可证 %r 不在内置许可证兼容矩阵中（规范化结果：%s）。"
            "预演仅支持矩阵内置的 SPDX 许可证：%s。" % (text, display, supported)
        )
    return token


# --- 预演结果构建 -------------------------------------------------------------


def _node_brief(node: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if node is None:
        return None
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "version": node.get("version"),
        "version_unspecified": node.get("version_unspecified", False),
        "license_raw": node.get("license_raw"),
        "license_display": node.get("license_display"),
        "license": node.get("license"),
        "license_known": node.get("license_known"),
        "license_category": node.get("license_category"),
        "conflict_count": node.get("conflict_count", 0),
    }


def _audit_meta(result: Dict[str, Any]) -> Dict[str, Any]:
    summary = result.get("summary") or {}
    return {
        "audit_id": result.get("audit_id"),
        "manifest_name": result.get("manifest_name"),
        "status": result.get("status"),
        "created_at": result.get("created_at"),
        "source_format": result.get("source_format"),
        "packages": summary.get("packages"),
        "edges": summary.get("edges"),
        "conflicts": summary.get("conflicts"),
        "license_warnings": summary.get("license_warnings"),
    }


def _conflict_index(
    result: Dict[str, Any],
) -> Dict[Tuple[str, str], Dict[str, Any]]:
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for conflict in result.get("conflicts", []) or []:
        # 分析器对同一 (ancestor, node) 只产出一条最短路径冲突
        index[(str(conflict["ancestor"]), str(conflict["node"]))] = conflict
    return index


def _fields_changed(
    before: Dict[str, Any],
    after: Dict[str, Any],
) -> List[str]:
    changed: List[str] = []
    if before.get("severity") != after.get("severity"):
        changed.append("severity")
    if before.get("status") != after.get("status"):
        changed.append("status")
    if before.get("ancestor_license") != after.get("ancestor_license"):
        changed.append("ancestor_license")
    if before.get("node_license") != after.get("node_license"):
        changed.append("node_license")
    if before.get("path") != after.get("path"):
        changed.append("path")
    if before.get("reason") != after.get("reason"):
        changed.append("reason")
    return changed


def _finding_sort_key(side: Dict[str, Any]) -> Tuple[int, int, str, str]:
    return (
        0 if side.get("severity") == "error" else 1,
        int(side.get("distance", 0)),
        str(side.get("node", "")),
        str(side.get("ancestor", "")),
    )


def _role_of(ancestor: str, node: str, swapped_id: str) -> str:
    if ancestor == swapped_id:
        return ROLE_AS_ANCESTOR
    if node == swapped_id:
        return ROLE_AS_DEPENDENCY
    return ROLE_UNRELATED


def _make_finding(
    key: Tuple[str, str],
    change: str,
    swapped_id: str,
    before: Optional[Dict[str, Any]],
    after: Optional[Dict[str, Any]],
    fields_changed: Optional[List[str]] = None,
) -> Dict[str, Any]:
    present = after if after is not None else before
    assert present is not None
    return {
        "change": change,
        "role": _role_of(key[0], key[1], swapped_id),
        "ancestor": key[0],
        "node": key[1],
        "before": before,
        "after": after,
        "fields_changed": fields_changed or [],
        "severity_before": before.get("severity") if before else None,
        "severity_after": after.get("severity") if after else None,
        "distance_before": before.get("distance") if before else None,
        "distance_after": after.get("distance") if after else None,
        "sort_key": _finding_sort_key(present),
    }


def _pair_conflicts(
    before_result: Dict[str, Any],
    after_result: Dict[str, Any],
    swapped_id: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    before_index = _conflict_index(before_result)
    after_index = _conflict_index(after_result)

    added: List[Dict[str, Any]] = []
    removed: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []
    for key in sorted(set(before_index) | set(after_index)):
        in_before = before_index.get(key)
        in_after = after_index.get(key)
        if in_before is None:
            added.append(_make_finding(key, ADDED, swapped_id, None, in_after))
        elif in_after is None:
            removed.append(_make_finding(key, REMOVED, swapped_id, in_before, None))
        else:
            fields_changed = _fields_changed(in_before, in_after)
            if fields_changed:
                changed.append(
                    _make_finding(key, CHANGED, swapped_id, in_before, in_after, fields_changed)
                )
    for bucket in (added, removed, changed):
        bucket.sort(key=lambda item: item["sort_key"])
        for item in bucket:
            item.pop("sort_key", None)
    return added, removed, changed


def _rehearsed_result(
    result: Dict[str, Any],
    target_node: Dict[str, Any],
    candidate_token: str,
) -> Dict[str, Any]:
    """仅替换目标节点许可证，沿原依赖图重算传递约束与冲突（深拷贝，不改写输入）。"""
    nodes: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for node in result.get("nodes", []) or []:
        clone = copy.deepcopy(node)
        clone["constraints"] = []
        clone["conflict_count"] = 0
        if clone.get("id") == target_node["id"]:
            info = lic.license_info(candidate_token)
            clone["license_raw"] = candidate_token
            clone["license_display"] = info["display"]
            clone["license"] = info["token"]
            clone["license_known"] = info["known"]
            clone["license_category"] = info["category"]
        nodes[clone["id"]] = clone
        order.append(clone["id"])

    edges = copy.deepcopy(result.get("edges", []) or [])
    unresolved = copy.deepcopy(result.get("unresolved", []) or [])
    # 已存结果的 warnings 同时包含解析告警与由 unresolved 自动追加的告警；
    # _build_result 会依据 unresolved 再追加一次，这里先扣除自动部分以免重复。
    auto_unresolved = {
        "未解析依赖：%s -> %s（%s）" % (u.get("source"), u.get("reference"), u.get("reason"))
        for u in unresolved
    }
    parse_warnings = [
        w for w in (result.get("warnings", []) or []) if w not in auto_unresolved
    ]

    rehearsed = analyzer._build_result(
        str(result.get("manifest_name") or "rehearsed"),
        None,
        nodes,
        order,
        edges,
        unresolved,
        parse_warnings,
    )
    if result.get("source_format"):
        rehearsed["source_format"] = result["source_format"]
    return rehearsed


def rehearse_license_swap(
    result: Dict[str, Any],
    package_ref: str,
    candidate_license: str,
) -> Dict[str, Any]:
    """对一份已保存审计做单包许可证替换预演，返回预演报告（只读，不改写输入）。

    包不存在或候选许可证不在内置矩阵时抛出 ``ValueError``（API 层转为 422）。
    """
    swapped_id = resolve_package(result, package_ref)
    candidate_token = resolve_candidate_license(candidate_license)

    node_map = {str(n.get("id")): n for n in result.get("nodes", []) or []}
    target_node = node_map[swapped_id]
    candidate_info = lic.license_info(candidate_token)

    before_counts = {
        "conflicts": int((result.get("summary") or {}).get("conflicts") or 0),
        "warnings": int((result.get("summary") or {}).get("license_warnings") or 0),
        "total": len(result.get("conflicts", []) or []),
    }

    rehearsed = _rehearsed_result(result, target_node, candidate_token)
    after_counts = {
        "conflicts": int(rehearsed["summary"]["conflicts"]),
        "warnings": int(rehearsed["summary"]["license_warnings"]),
        "total": len(rehearsed["conflicts"]),
    }

    added, removed, changed = _pair_conflicts(result, rehearsed, swapped_id)

    def _roles(bucket: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {ROLE_AS_ANCESTOR: 0, ROLE_AS_DEPENDENCY: 0, ROLE_UNRELATED: 0}
        for item in bucket:
            counts[item["role"]] += 1
        return counts

    def _errors(bucket: List[Dict[str, Any]]) -> int:
        return sum(
            1
            for item in bucket
            if (item["after"] or item["before"]).get("severity") == "error"
        )

    def _severity_flips(bucket: List[Dict[str, Any]]) -> Dict[str, int]:
        flips = {"error_to_warning": 0, "warning_to_error": 0}
        for item in bucket:
            b, a = item.get("severity_before"), item.get("severity_after")
            if b == "error" and a == "warning":
                flips["error_to_warning"] += 1
            elif b == "warning" and a == "error":
                flips["warning_to_error"] += 1
        return flips

    flips = _severity_flips(changed)
    net = {
        "conflicts": after_counts["conflicts"] - before_counts["conflicts"],
        "warnings": after_counts["warnings"] - before_counts["warnings"],
        "total": after_counts["total"] - before_counts["total"],
    }

    return {
        "kind": KIND,
        "read_only": True,
        "direction": DIRECTION,
        "rehearsed": True,
        "field_labels": FIELD_LABELS,
        "role_labels": ROLE_LABELS,
        "audit": _audit_meta(result),
        "package": {
            "requested": str(package_ref or "").strip(),
            "id": swapped_id,
            "name": target_node.get("name"),
            "version": target_node.get("version"),
            "version_unspecified": target_node.get("version_unspecified", False),
            "before": _node_brief(target_node),
            "after": {
                "license": candidate_info["token"],
                "license_display": candidate_info["display"],
                "license_category": candidate_info["category"],
                "license_known": candidate_info["known"],
            },
            "unchanged_license": target_node.get("license") == candidate_info["token"],
        },
        "candidate_license": candidate_info["token"],
        "status_before": result.get("status"),
        "status_after": rehearsed.get("status"),
        "summary": {
            "before": {
                "status": result.get("status"),
                "conflicts": before_counts["conflicts"],
                "warnings": before_counts["warnings"],
                "total": before_counts["total"],
            },
            "after": {
                "status": rehearsed.get("status"),
                "conflicts": after_counts["conflicts"],
                "warnings": after_counts["warnings"],
                "total": after_counts["total"],
            },
            "net": net,
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "added_errors": _errors(added),
            "removed_errors": _errors(removed),
            "changed_errors": _errors(changed),
            "severity_flips": flips,
            "roles": {
                "added": _roles(added),
                "removed": _roles(removed),
                "changed": _roles(changed),
            },
        },
        # 预演后的节点简表（供网页在两侧路径上标注预演后的许可证）
        "nodes_after": [_node_brief(n) for n in rehearsed.get("nodes", [])],
        "added": added,
        "removed": removed,
        "changed": changed,
    }
