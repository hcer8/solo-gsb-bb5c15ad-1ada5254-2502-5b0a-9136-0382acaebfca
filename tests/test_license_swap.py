"""单包许可证替换预演的自测（无测试框架依赖）：python -m tests.test_license_swap

使用独立临时 SQLite 库验证只读性，不触碰 ./data；
核心逻辑只依赖 analyzer/cyclonedx/license_swap，无需安装 fastapi 即可运行。
"""

from __future__ import annotations

import copy
import tempfile
from pathlib import Path

from app import analyzer, cyclonedx, database, license_swap as swap

# 隔离的临时数据库（仅用于只读性验证）
_TMP_DIR = tempfile.mkdtemp(prefix="license-swap-test-")
database.DB_PATH = Path(_TMP_DIR) / "test.db"
database.init_db()


def _check(name: str, condition: bool, detail: str = "") -> None:
    if not condition:
        raise AssertionError("%s %s" % (name, detail))
    print("ok -", name)


def _expect_error(name: str, fn, needle: str) -> None:
    try:
        fn()
    except ValueError as exc:
        _check(name, needle in str(exc), "message=%r" % str(exc))
        return
    raise AssertionError("%s 未抛出 ValueError" % name)


def _demo_manifest():
    # app(GPL-2.0) -> mid(MIT) -> leaf(Apache-2.0)：app→leaf 专利条款硬冲突（2 跳）
    # app -> perm(MIT) 兼容；prop(Proprietary) -> leaf(Apache-2.0) 兼容。
    return {
        "name": "swap-demo",
        "packages": [
            {"name": "app", "version": "1", "license": "GPL-2.0",
             "dependencies": ["mid@1", "perm@1"]},
            {"name": "mid", "version": "1", "license": "MIT",
             "dependencies": ["leaf@1"]},
            {"name": "leaf", "version": "1", "license": "Apache-2.0"},
            {"name": "perm", "version": "1", "license": "MIT"},
            {"name": "prop", "version": "1", "license": "Proprietary",
             "dependencies": ["leaf@1"]},
        ],
    }


def _demo_result():
    return analyzer.analyze_manifest(_demo_manifest())


def _finding_map(report, bucket):
    return {(f["ancestor"], f["node"]): f for f in report[bucket]}


def test_resolve_package() -> None:
    result = _demo_result()
    _check("exact id", swap.resolve_package(result, "app@1") == "app@1")
    _check("case-insensitive id", swap.resolve_package(result, "APP@1") == "app@1")
    _check("unique name", swap.resolve_package(result, "leaf") == "leaf@1")
    _expect_error(
        "missing package rejected",
        lambda: swap.resolve_package(result, "ghost@9"),
        "审计中不存在包：ghost@9",
    )
    _expect_error(
        "empty package rejected",
        lambda: swap.resolve_package(result, "  "),
        "请指定要替换许可证的包",
    )
    two_versions = analyzer.analyze_manifest(
        {"packages": [
            {"name": "x", "version": "1", "license": "MIT"},
            {"name": "x", "version": "2", "license": "MIT"},
        ]}
    )
    _expect_error(
        "ambiguous name rejected",
        lambda: swap.resolve_package(two_versions, "x"),
        "匹配到多个版本",
    )
    _check("ambiguous resolvable with id", swap.resolve_package(two_versions, "x@2") == "x@2")


def test_resolve_candidate_license() -> None:
    _check("canonical token", swap.resolve_candidate_license("Apache-2.0") == "Apache-2.0")
    _check("alias token", swap.resolve_candidate_license("gplv3") == "GPL-3.0")
    _check("chinese alias style", swap.resolve_candidate_license("MIT License") == "MIT")
    _expect_error(
        "unknown license rejected",
        lambda: swap.resolve_candidate_license("OFL-1.1"),
        "不在内置许可证兼容矩阵中",
    )
    _expect_error(
        "empty license rejected",
        lambda: swap.resolve_candidate_license(""),
        "请指定候选 SPDX 许可证",
    )
    _expect_error(
        "unlicensed rejected",
        lambda: swap.resolve_candidate_license("UNLICENSED"),
        "不在内置许可证兼容矩阵中",
    )


def test_swap_ancestor_removes_conflict() -> None:
    result = _demo_result()
    _check("baseline has one error", result["summary"]["conflicts"] == 1, str(result["summary"]))
    report = swap.rehearse_license_swap(result, "app@1", "MIT")

    _check("read only flag", report["read_only"] is True)
    _check("rehearsed flag", report["rehearsed"] is True)
    _check("kind", report["kind"] == swap.KIND)
    _check("package echoed", report["package"]["id"] == "app@1")
    _check(
        "before/after license",
        (report["package"]["before"]["license"], report["package"]["after"]["license"])
        == ("GPL-2.0", "MIT"),
    )
    _check("status after clean", report["status_after"] == "clean", report["status_after"])

    removed = _finding_map(report, "removed")
    _check("one removed", set(removed) == {("app@1", "leaf@1")}, str(set(removed)))
    f = removed[("app@1", "leaf@1")]
    _check("role as ancestor", f["role"] == swap.ROLE_AS_ANCESTOR)
    _check("removed carries before only", f["before"] is not None and f["after"] is None)
    _check(
        "original shortest path kept",
        f["before"]["path"] == ["app@1", "mid@1", "leaf@1"],
        str(f["before"]["path"]),
    )
    _check("no added/changed", report["added"] == [] and report["changed"] == [])

    s = report["summary"]
    _check("net conflicts -1", s["net"]["conflicts"] == -1, str(s["net"]))
    _check("net total -1", s["net"]["total"] == -1)
    _check("removed errors 1", s["removed_errors"] == 1)
    _check("removed role counts", s["roles"]["removed"] == {"as_ancestor": 1, "as_dependency": 0, "unrelated": 0})


def test_swap_dependency_removes_and_others_intact() -> None:
    result = _demo_result()
    report = swap.rehearse_license_swap(result, "leaf@1", "MIT")
    removed = _finding_map(report, "removed")
    _check("removed via dependency", set(removed) == {("app@1", "leaf@1")}, str(set(removed)))
    _check("role as dependency", removed[("app@1", "leaf@1")]["role"] == swap.ROLE_AS_DEPENDENCY)
    _check("net conflicts -1", report["summary"]["net"]["conflicts"] == -1)
    # 其余原兼容组合仍兼容：无新增
    _check("no added", report["added"] == [])


def test_swap_adds_conflict() -> None:
    result = _demo_result()
    # perm(MIT) 换成 GPL-3.0：app(GPL-2.0) -> perm(GPL-3.0) 方向不兼容，新增硬冲突
    report = swap.rehearse_license_swap(result, "perm@1", "GPL-3.0")
    added = _finding_map(report, "added")
    _check("new app->perm conflict", set(added) == {("app@1", "perm@1")}, str(set(added)))
    f = added[("app@1", "perm@1")]
    _check("added role as dependency", f["role"] == swap.ROLE_AS_DEPENDENCY)
    _check("added is error", f["after"]["severity"] == "error")
    _check("added carries after only", f["before"] is None and f["after"] is not None)
    _check("added path", f["after"]["path"] == ["app@1", "perm@1"])
    _check("net conflicts +1", report["summary"]["net"]["conflicts"] == 1)
    _check("added errors 1", report["summary"]["added_errors"] == 1)
    _check("status stays conflict", report["status_after"] == "conflict")
    _check("original app->leaf still removed bucket empty", report["removed"] == [])
    # 原 app->leaf 冲突仍存在且内容不变（不在任何差异桶里）
    all_changed_keys = {
        (f["ancestor"], f["node"])
        for bucket in ("added", "removed", "changed") for f in report[bucket]
    }
    _check("unchanged pair omitted", ("app@1", "leaf@1") not in all_changed_keys)


def test_severity_flip_warning_to_error() -> None:
    result = analyzer.analyze_manifest(
        {"packages": [
            {"name": "a", "version": "1", "license": "MIT", "dependencies": ["p@1"]},
            {"name": "p", "version": "1", "license": "Proprietary"},
        ]}
    )
    _check("baseline warning only", result["status"] == "warning", result["status"])
    report = swap.rehearse_license_swap(result, "a@1", "GPL-3.0")
    _check("one changed", len(report["changed"]) == 1, str(report["changed"]))
    f = report["changed"][0]
    _check("pair key", (f["ancestor"], f["node"]) == ("a@1", "p@1"))
    _check("severity flips", f["severity_before"] == "warning" and f["severity_after"] == "error")
    _check("fields include severity", "severity" in f["fields_changed"], str(f["fields_changed"]))
    _check("fields include status", "status" in f["fields_changed"])
    _check("fields include ancestor license", "ancestor_license" in f["fields_changed"])
    _check("both paths attached", f["before"]["path"] == f["after"]["path"] == ["a@1", "p@1"])
    s = report["summary"]
    _check("flips counted", s["severity_flips"]["warning_to_error"] == 1, str(s["severity_flips"]))
    _check("net errors +1", s["net"]["conflicts"] == 1)
    _check("net warnings -1", s["net"]["warnings"] == -1)
    _check("net total 0", s["net"]["total"] == 0)
    _check("status flips to conflict", report["status_after"] == "conflict")


def test_unchanged_license_is_noop() -> None:
    result = _demo_result()
    report = swap.rehearse_license_swap(result, "app@1", "gpl-2.0")  # 别名指向同一许可证
    _check("unchanged flag", report["package"]["unchanged_license"] is True)
    _check("all buckets empty", report["added"] == [] and report["removed"] == [] and report["changed"] == [])
    _check("all net zero", report["summary"]["net"] == {"conflicts": 0, "warnings": 0, "total": 0})


def test_only_target_node_changes() -> None:
    result = _demo_result()
    report = swap.rehearse_license_swap(result, "mid@1", "Apache-2.0")
    before_map = {n["id"]: n["license"] for n in result["nodes"]}
    after_map = {n["id"]: n["license"] for n in report["nodes_after"]}
    _check("target license replaced", after_map["mid@1"] == "Apache-2.0")
    others = [nid for nid in before_map if nid != "mid@1"]
    _check("other licenses untouched", all(after_map[n] == before_map[n] for n in others))
    _check("node count stable", len(after_map) == len(before_map))


def test_cyclonedx_audit_supported() -> None:
    bom = {
        "bomFormat": "CycloneDX",
        "components": [
            {"bom-ref": "app", "name": "app", "version": "1",
             "licenses": [{"license": {"id": "GPL-2.0"}}]},
            {"bom-ref": "lib", "name": "lib", "version": "1",
             "licenses": [{"license": {"id": "Apache-2.0"}}]},
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["lib"]}],
    }
    result = cyclonedx.analyze_bom(bom)
    _check("cyclonedx baseline conflict", result["status"] == "conflict", result.get("error"))
    report = swap.rehearse_license_swap(result, "app@1", "MIT")
    _check("source format carried", report["audit"]["source_format"] == "cyclonedx")
    removed = _finding_map(report, "removed")
    _check("cyclonedx conflict removed", set(removed) == {("app@1", "lib@1")}, str(set(removed)))
    _check("cyclonedx original path", removed[("app@1", "lib@1")]["before"]["path"] == ["app@1", "lib@1"])
    # 候选许可证不在矩阵
    _expect_error(
        "cyclonedx unknown license rejected",
        lambda: swap.rehearse_license_swap(result, "lib@1", "JSON-1.0"),
        "不在内置许可证兼容矩阵中",
    )
    _expect_error(
        "cyclonedx missing package rejected",
        lambda: swap.rehearse_license_swap(result, "nope@1", "MIT"),
        "审计中不存在包：nope@1",
    )


def test_rehearsal_is_read_only() -> None:
    manifest = _demo_manifest()
    result = analyzer.analyze_manifest(manifest)
    audit_id = database.save_audit(result, manifest)

    stored_before = database.get_audit(audit_id)
    audits_before = database.list_audits(limit=500)
    reviews_before = database.list_reviews(limit=500)

    snapshot = copy.deepcopy(stored_before)
    report = swap.rehearse_license_swap(stored_before, "app@1", "MIT")
    _check("report produced", report["rehearsed"] is True)
    _check("input result not mutated", stored_before == snapshot)
    _check("no new audit created", database.list_audits(limit=500) == audits_before)
    _check("stored audit unchanged", database.get_audit(audit_id) == snapshot)
    _check("reviews untouched", database.list_reviews(limit=500) == reviews_before)
    _check("missing audit stays missing", database.get_audit(999999) is None)


def test_unresolved_warnings_not_duplicated() -> None:
    # 含未解析依赖：其自动告警在已存结果 warnings 中已存在，预演重算不应重复追加。
    result = analyzer.analyze_manifest(
        {"packages": [
            {"name": "app", "version": "1", "license": "MIT",
             "dependencies": ["missing@1"]},
        ]}
    )
    _check("baseline unresolved", len(result.get("unresolved", [])) == 1, str(result.get("unresolved")))
    # nodes_after 只给节点简表；unresolved/warnings 行为通过重算结果直接验证
    rehearsed = swap._rehearsed_result(result, result["nodes"][0], "Apache-2.0")
    _check(
        "unresolved preserved",
        rehearsed.get("unresolved") == result.get("unresolved"),
        str(rehearsed.get("unresolved")),
    )
    _check(
        "warnings not duplicated",
        rehearsed.get("warnings") == result.get("warnings"),
        "%r != %r" % (rehearsed.get("warnings"), result.get("warnings")),
    )
    _check("status consistent", rehearsed.get("status") == result.get("status"))


def main() -> None:
    test_resolve_package()
    test_resolve_candidate_license()
    test_swap_ancestor_removes_conflict()
    test_swap_dependency_removes_and_others_intact()
    test_swap_adds_conflict()
    test_severity_flip_warning_to_error()
    test_unchanged_license_is_noop()
    test_only_target_node_changes()
    test_cyclonedx_audit_supported()
    test_unresolved_warnings_not_duplicated()
    test_rehearsal_is_read_only()
    print("\nall license-swap tests passed.")


if __name__ == "__main__":
    main()
