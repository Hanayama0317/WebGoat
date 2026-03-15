# SAST 大量検知対応 指南書

> 対象リポジトリ: WebGoat
> 作成日: 2026-03-15
> 想定読者: 開発者・セキュリティ担当者

---

## はじめに ― なぜ 3,000 件出るのか

SAST を初めて導入した直後に大量の検知が出るのはよくある現象です。
原因は大きく 3 つに分類できます。

| 分類 | 割合の目安 | 対処方針 |
|---|---|---|
| **誤検知 (False Positive)** | 30〜50% | ルール抑制・アノテーションで除外 |
| **既存の技術的負債** | 40〜60% | 段階的修正（後述のフェーズ計画） |
| **実際に直すべき脆弱性** | 5〜20% | 優先修正 |

WebGoat は **意図的に脆弱に設計された教育用アプリ** です。
レッスンコード (`webgoat-lessons/`) の検知の多くは設計上のものであり、
**修正対象は `webgoat-container/` と `webgoat-server/` の実装コードに絞る** ことが現実的です。

---

## 全体戦略 ― 3 つの原則

### 原則 1: 過去の負債と未来の新規を分ける

```
[現在の 3,000 件] ─── 既存負債として計画的に削減
[今後の新規コード] ─── 新規検知はゼロを目標にブロック
```

既存の全件を一度に直そうとすると開発が止まります。
**「今日以降のコードに新しい脆弱性を増やさない」** を最初のゴールにしてください。

### 原則 2: 重要度でフィルタリングして集中する

全件を均等に扱わず、以下の順で対処します。

```
Critical / High  ←── まず全件対処
Medium          ←── スプリントに組み込んで削減
Low / Info      ←── バックログに積む（最後）
```

### 原則 3: 誤検知を正直にコードに記録する

抑制はサイレントに行わず、**なぜ無視するかをコードに残す** ことで
レビュアーと将来の自分への説明責任を果たします。

---

## フェーズ別 実行計画

### Phase 0: 現状把握（1〜2 日）

まず「何が何件あるか」を数字で把握します。

```bash
# GitHub CLI で SARIF をダウンロードして件数を確認
gh run download <run_id> --repo Hanayama0317/WebGoat \
  --name codeql-sarif-java \
  --name semgrep-results \
  --name spotbugs-sarif

# 重要度別件数を確認
python3 - <<'EOF'
import json, glob, collections

for sarif_file in glob.glob("**/*.sarif", recursive=True):
    data = json.load(open(sarif_file))
    counts = collections.Counter()
    for run in data.get("runs", []):
        for result in run.get("results", []):
            counts[result.get("level", "warning")] += 1
    print(f"{sarif_file}: {dict(counts)}")
EOF
```

**目標**: ツール別・重要度別の件数一覧表を作る

---

### Phase 1: ノイズ除去（1 週間）

実際に直すべき件数を絞り込みます。目安として **50〜60% 削減** を目指します。

#### 1-1. WebGoat レッスンコードを除外対象に設定

`webgoat-lessons/` はすべて意図的な脆弱性です。
各ツールの設定で除外します。

**CodeQL** (`.github/codeql-config.yml` を作成):
```yaml
paths-ignore:
  - "webgoat-lessons/**"
  - "webwolf/**"
```

`.github/workflows/devsecops.yml` の CodeQL init ステップに追記:
```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: ${{ matrix.language }}
    queries: security-extended,security-and-quality
    config-file: .github/codeql-config.yml   # ← 追加
```

**Semgrep** (`.semgrepignore` をルートに作成):
```
# 意図的に脆弱なレッスンコード
webgoat-lessons/
webwolf/

# テストコード（誤検知が多い）
**/test/**
**/tests/**
**/*Test.java
**/*Tests.java
```

**SpotBugs** (`pom.xml` の spotbugs-maven-plugin 設定に追加):
```xml
<configuration>
  <excludeFilterFile>.github/spotbugs-exclude.xml</excludeFilterFile>
</configuration>
```

`.github/spotbugs-exclude.xml`:
```xml
<FindBugsFilter>
  <!-- レッスンコードは除外 -->
  <Match>
    <Package name="~org\.owasp\.webgoat\.lessons.*" />
  </Match>
  <!-- テストコードは除外 -->
  <Match>
    <Class name="~.*Test$" />
  </Match>
</FindBugsFilter>
```

#### 1-2. 誤検知ルールの特定と抑制

SARIF ファイルを確認し、同じ `ruleId` が大量に出ているものを調査します。
誤検知と判断したルールは以下の方法で抑制します。

**Semgrep のインライン抑制**（コード上で個別抑制）:
```java
// nosemgrep: java.lang.security.audit.script-injection
String query = buildQuery(input);
```

**SpotBugs のアノテーション抑制**:
```java
@SuppressFBWarnings(
    value = "SQL_INJECTION_JDBC",
    justification = "入力値はホワイトリスト検証済み。L.42 の validateInput() 参照"
)
public ResultSet execute(String validated) { ... }
```

**CodeQL のインライン抑制**:
```java
// lgtm[java/sql-injection]
String sql = "SELECT * FROM " + tableEnum.name();
```

#### 1-3. OWASP Dependency-Check の抑制

`.github/owasp-suppressions.xml` に誤検知を記録します:
```xml
<suppress>
  <notes>
    WebGoatの教育目的依存ライブラリ。本番利用しない。
    確認日: 2026-03-15 / 確認者: security-team
  </notes>
  <packageUrl regex="true">^pkg:maven/org\.owasp\.webgoat/.*$</packageUrl>
  <cve>CVE-XXXX-XXXXX</cve>
</suppress>
```

---

### Phase 2: 新規コードのゲート設定（Phase 1 完了後すぐ）

**今日以降のコードに脆弱性を増やさない** ための仕組みを入れます。

#### PR 時に新規検知のみをチェックする

`.github/workflows/devsecops.yml` の Semgrep を PR 向けに差分スキャンに変更:

```yaml
- name: Run Semgrep (差分スキャン)
  if: github.event_name == 'pull_request'
  run: |
    semgrep ci \
      --config "p/java" \
      --config "p/owasp-top-ten" \
      --config "p/spring-security" \
      --sarif \
      --output semgrep-results.sarif
      # PR では変更ファイルのみ自動的にスキャン
  env:
    SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
```

#### Security Gate を既存負債では失敗させない

現状の Security Gate は全件をチェックしています。
既存負債のみに起因する失敗でパイプラインが止まらないよう、
**`continue-on-error: true`** を一時的に設定し、Phase 3 完了後に外します。

```yaml
sast-spotbugs:
  continue-on-error: true   # Phase 3 完了まで一時的に設定
```

---

### Phase 3: 既存負債の計画的修正（スプリント単位）

Phase 1 でノイズを除いた残りの件数を、スプリントに分割して修正します。

#### 優先度マトリクス

| 優先度 | 条件 | 目標期限 |
|---|---|---|
| P0（即対応） | Critical + 本番コードへの影響あり | 今週中 |
| P1（高） | High + 本番コード | 今スプリント |
| P2（中） | Medium / High + テストコード | 次の 2 スプリント |
| P3（低） | Low / Info、またはレッスンコード | バックログ |

#### スプリントへの組み込み方

1. SARIF を GitHub Security タブで開く (`Security` → `Code scanning`)
2. `Tool` フィルターで各ツールを絞り込む
3. `Severity: Critical, High` でフィルター
4. 件数を確認し、1 スプリントあたり **20〜30 件** を目安に Issue 化
5. 各 Issue に対象ファイル・行番号・修正方針を記載

---

### Phase 4: 定常運用（Phase 3 完了後）

#### KPI と目標値

| 指標 | 初期値 | 3ヶ月目標 | 6ヶ月目標 |
|---|---|---|---|
| Critical/High 件数 | ~3,000 | 500 以下 | 50 以下 |
| 新規 PR での新規検知数 | 計測開始 | 5 以下/PR | 0 |
| 誤検知率 | 未計測 | 30% 以下 | 20% 以下 |
| 平均修正リードタイム | 未計測 | 7 日以内 | 3 日以内 |

#### 週次レビュー

毎週、以下を確認します:
- GitHub Security タブの未対応 Critical/High 件数
- 新規 PR で検知されたアラート
- 抑制ファイルの追加状況（抑制が増えすぎていないか）

---

## ツール別 クイックリファレンス

### GitHub Security タブでの確認方法

```
リポジトリ → Security → Code scanning alerts
  ├── Tool: CodeQL / Semgrep / SpotBugs でフィルター
  ├── Severity: Critical / High でフィルター
  └── State: Open のみ表示
```

### SARIF アーティファクトのダウンロード

```bash
# 最新の実行 ID を確認
gh run list --repo Hanayama0317/WebGoat --workflow=devsecops.yml --limit=1

# アーティファクトをダウンロード
gh run download <run_id> --repo Hanayama0317/WebGoat --name codeql-sarif-java
gh run download <run_id> --repo Hanayama0317/WebGoat --name semgrep-results
gh run download <run_id> --repo Hanayama0317/WebGoat --name spotbugs-sarif
```

### SARIF ビューア

ローカルで SARIF ファイルを見やすく確認するには:
- **VS Code**: [SARIF Viewer 拡張機能](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- **Web**: [Microsoft SARIF Web Viewer](https://microsoft.github.io/sarif-web-component/)
- **GitHub**: Security タブで直接確認（ソースコードへのリンク付き）

---

## まとめ ― 実行順序チェックリスト

```
[ ] Phase 0: SARIF をダウンロードし、ツール別・重要度別の件数を把握する
[ ] Phase 1-1: webgoat-lessons/ をスキャン対象から除外する設定を追加
[ ] Phase 1-2: 上位 10 ルールの誤検知を調査・抑制する
[ ] Phase 1-3: OWASP Dependency-Check の誤検知を suppressions.xml に記録
[ ] Phase 2: PR の差分スキャンを設定し「新規ゼロ」ゲートを有効化
[ ] Phase 3: 残存 Critical/High を Issue 化してスプリントに分割
[ ] Phase 4: 週次 KPI レビューを定常化
```

> **重要**: Phase 1 の除外・抑制は必ずコードレビューを通してください。
> 誤った抑制は本物の脆弱性を隠します。
> 「なぜ抑制するか」を必ず `justification` や `notes` に記録してください。
