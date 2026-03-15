#!/usr/bin/env python3
"""
SpotBugs XML (BugCollection) → SARIF 2.1.0 コンバーター
使い方: python3 spotbugs-to-sarif.py <input_xml_or_dir> <output.sarif>
  - input に XML ファイルを指定 → そのファイルを変換
  - input にディレクトリを指定 → 配下の spotbugsXml.xml を再帰検索してマージ変換
"""

import json
import os
import sys
import glob
import xml.etree.ElementTree as ET

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec"
    "/master/Schemata/sarif-schema-2.1.0.json"
)

# SpotBugs priority → SARIF level
PRIORITY_TO_LEVEL = {"1": "error", "2": "warning", "3": "note"}

# SpotBugs category → CWE タグ (主要なもの)
CATEGORY_TO_TAGS = {
    "SECURITY": ["security"],
    "MALICIOUS_CODE": ["security"],
    "SQL": ["security", "injection"],
    "XSS": ["security"],
    "CORRECTNESS": ["correctness"],
    "PERFORMANCE": ["performance"],
    "BAD_PRACTICE": ["best-practice"],
    "MT_CORRECTNESS": ["concurrency"],
}


def collect_xml_files(path: str) -> list[str]:
    if os.path.isfile(path):
        return [path]
    # ディレクトリの場合は spotbugsXml.xml を再帰検索
    pattern = os.path.join(path, "**", "spotbugsXml.xml")
    files = glob.glob(pattern, recursive=True)
    if not files:
        # フォールバック: 任意の .xml を対象にする
        pattern = os.path.join(path, "**", "*.xml")
        files = glob.glob(pattern, recursive=True)
    return sorted(files)


def parse_bug_collection(xml_file: str) -> tuple[list, list]:
    """BugCollection XML をパースして (rules, results) を返す"""
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError as e:
        print(f"[WARN] XML パース失敗: {xml_file}: {e}", file=sys.stderr)
        return [], []

    root = tree.getroot()
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for bug in root.findall(".//BugInstance"):
        bug_type = bug.get("type", "UNKNOWN")
        category = bug.get("category", "")
        priority = bug.get("priority", "3")
        rank = int(bug.get("rank", "20"))
        level = PRIORITY_TO_LEVEL.get(priority, "warning")

        # メッセージ取得
        long_msg_el = bug.find("LongMessage")
        short_msg_el = bug.find("ShortMessage")
        message = (
            (long_msg_el.text or "").strip()
            if long_msg_el is not None
            else (short_msg_el.text or "").strip()
            if short_msg_el is not None
            else bug_type
        )

        # ソース位置取得（primary 優先、なければ最初の SourceLine）
        src = bug.find('.//SourceLine[@primary="true"]')
        if src is None:
            src = bug.find(".//SourceLine")

        if src is None:
            # ソース情報がない場合はスキップ
            continue

        source_file = src.get("sourcepath") or src.get("sourcefile") or ""
        try:
            start_line = max(1, int(src.get("start", "1")))
            end_line = max(start_line, int(src.get("end", str(start_line))))
        except ValueError:
            start_line, end_line = 1, 1

        # ルール登録
        if bug_type not in rules:
            tags = CATEGORY_TO_TAGS.get(category, [category.lower()]) if category else []
            rules[bug_type] = {
                "id": bug_type,
                "name": bug_type,
                "shortDescription": {"text": bug_type},
                "fullDescription": {
                    "text": message or f"SpotBugs rule: {bug_type} (category: {category})"
                },
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": tags,
                    "precision": "medium",
                    "problem.severity": level,
                    "security-severity": str(max(1.0, 10.0 - rank * 0.4)),
                },
                "helpUri": (
                    f"https://spotbugs.readthedocs.io/en/stable/bugDescriptions.html#{bug_type}"
                ),
            }

        results.append(
            {
                "ruleId": bug_type,
                "level": level,
                "message": {"text": message or bug_type},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": source_file,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": start_line,
                                "endLine": end_line,
                            },
                        }
                    }
                ],
            }
        )

    return list(rules.values()), results


def build_sarif(all_rules: list, all_results: list) -> dict:
    # ルール重複排除 (id でユニーク化)
    seen: set[str] = set()
    unique_rules = []
    for r in all_rules:
        if r["id"] not in seen:
            seen.add(r["id"])
            unique_rules.append(r)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SpotBugs",
                        "version": "4.x",
                        "informationUri": "https://spotbugs.github.io/",
                        "rules": unique_rules,
                    }
                },
                "results": all_results,
            }
        ],
    }


def main():
    if len(sys.argv) < 3:
        print(f"使い方: {sys.argv[0]} <xml_file_or_dir> <output.sarif>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    xml_files = collect_xml_files(input_path)
    if not xml_files:
        print(f"[WARN] XML ファイルが見つかりません: {input_path}", file=sys.stderr)
        # 空の SARIF を出力して後続ステップを継続させる
        sarif = build_sarif([], [])
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        print(f"[INFO] 空の SARIF を出力: {output_path}")
        return

    all_rules, all_results = [], []
    for xml_file in xml_files:
        print(f"[INFO] 変換中: {xml_file}", file=sys.stderr)
        rules, results = parse_bug_collection(xml_file)
        all_rules.extend(rules)
        all_results.extend(results)

    sarif = build_sarif(all_rules, all_results)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, ensure_ascii=False)

    print(
        f"[INFO] SARIF 出力完了: {output_path} "
        f"(rules={len(sarif['runs'][0]['tool']['driver']['rules'])}, "
        f"results={len(sarif['runs'][0]['results'])})"
    )


if __name__ == "__main__":
    main()
