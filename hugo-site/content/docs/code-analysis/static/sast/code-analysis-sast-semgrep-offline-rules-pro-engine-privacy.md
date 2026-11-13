---
id: code-analysis-sast-semgrep-offline-rules-pro-engine-privacy
title: Semgrep 代码审计落地：本地 semgrep-rules 离线扫描、Pro 规则/引擎登录门槛与 --metrics 隐私控制
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: semgrep-offline-rules-pro-engine-audit-workflow
tags:
- semgrep
- sast
- code-audit
- static-analysis
- ruleset
- privacy
- metrics
- pro-engine
- vscode
cve: []
severity: low
confidence: high
status: draft
created: '2026-11-13'
updated: '2026-11-13'
url: /docs/code-analysis/static/sast/code-analysis-sast-semgrep-offline-rules-pro-engine-privacy/
draft: false
kb_aliases:
- Semgrep 离线规则库
- semgrep-rules 本地扫描
- semgrep --config p/php
- semgrep --pro
- semgrep ci
- --metrics off
- Semgrep Pro 规则
---

## 一句话结论

用 Semgrep 做代码审计时，落地要点不是安装而是三件事：把官方 `semgrep-rules` 仓库拉到本地用 `--config <本地目录>` 离线扫描（不经 Registry、不触发 metrics 上报）；知道 Registry 集合里的 Pro 规则与 `--pro` 引擎必须登录才有（同一 `p/php` 集合未登录只加载 16 条规则、登录后 45 条含 29 条 Pro，未登录强开 `--pro` 行为不一致）；处理敏感代码时用本地规则加 `--metrics off` 控制数据外发，输出重定向到文件仍需用 sed 去掉 ANSI 颜色字符。

## 原理

- **规则来源三种形态**：`--config` 既可以是 Registry 集合名（如 `p/php`、`p/phpcs-security-audit`、`p/owasp-top-ten`），也可以是本地规则目录/单 YAML/URL。Registry 集合会按需拉取并默认开启 metrics；本地目录离线可用、无 metrics。
- **社区规则与 Pro 规则的能力差**：社区规则多为“危险函数调用”模式匹配（例如 exec-use.yaml 用 `pattern: $FUNC(...)` + `metavariable-regex` 匹配 `exec|system|shell_exec|...`，只排除字面量参数），覆盖面窄且无污点分析；Pro 规则使用 `pattern-sources`（`$_REQUEST/$_GET/$_POST/$_FILES/$_COOKIE`）与 `pattern-sinks`（exec/system/passthru/shell_exec/反引号/proc_open/popen/pcntl_exec）做数据流匹配，能命中跨语句的注入链。两者都可能有漏报（sink 列表不完备），只适合作为候选生成器。
- **登录门槛**：Registry 里标 Pro 的规则只对 Team 及以上账户可用；未登录时同一 `p/php` 集合只加载 16 条规则，登录后加载 45 条（其中 29 条为 Pro）。`--pro` 引擎需先 `semgrep login` 再 `semgrep install-semgrep-pro`；未登录时带 `--pro` 会提示需要登录，且实测扫描时间/结果与不带 `--pro` 时不一致，重新登录后再扫结果又回到登录态——版本行为本身不稳定，审计结论要记录所用账户状态与规则数。
- **Pro 引擎的跨文件分析**：开启后可在文件/函数边界间追踪数据流，减少误报、引入新结果，代价是扫描时间与内存上升；官方说明只在完整扫描且 Java/JavaScript 上运行，实测其他语言亦有变化，属于观察结论而非承诺。
- **metrics 与隐私**：仅本地配置/命令行模式不收集；使用 Registry 规则会收集维护规则所需数据（含项目 URL）；登录后使用云平台/`semgrep ci` 会收集并上传结果。`--metrics auto/on/off` 可控制；敏感代码库应离线规则 + `--metrics off`。
- **`semgrep ci` 的前提**：Locally 模式也要先把源码目录初始化为 git 项目，否则报错；默认使用全部规则（实测 1591 条，其中 513 条 Pro），扫描结果上传到 Semgrep Cloud Platform。
- **输出坑**：`-o` 或重定向到文件时输出仍带 ANSI 颜色转义（加 `--no-force-color` 也一样），需要 `sed 's/\x1B\[[0-9;]*[mK]//g'` 清洗后才能正常阅读/入库。
- **为什么这算“技巧”**：这些差异直接决定审计的召回（规则数/Pro 污点规则）与合规（源码/项目信息是否外发），不掌握就会把“未登录只跑了 16 条社区规则”误当成完整扫描。

## 触发条件

- 需要对一个代码库做快速 SAST 初筛（示例为 PHP CMS 项目），具备源码与安装 semgrep 的 Python 环境（`pip install semgrep`）。
- 离线环境或敏感代码不能外发；或需要 Pro 污点规则/引擎提升召回。
- 本地规则库（`returntocorp/semgrep-rules`）与 semgrep 版本兼容；VSCode 集成需要安装 semgrep 插件。

## 利用步骤

1. 安装并确认版本：
   ```bash
   python3 -m pip install semgrep
   semgrep --version
   ```
2. 准备离线规则库：克隆官方社区规则仓库（`git clone https://github.com/returntocorp/semgrep-rules`），按目标语言选择子目录（如 `semgrep-rules/php`）。
3. 离线扫描（不经 Registry、无 metrics）：
   ```bash
   semgrep --config /path/semgrep-rules/php /path/to/project --metrics off
   ```
   同一项目用 Registry 集合对比，观察规则数与命中差异（示例：`--config p/phpcs-security-audit` 为 10 条规则/89 命中；本地 php 目录为 57 条规则/257 命中，两者规则集不同，不能把命中数直接当好坏）。
4. 需要 Pro 规则/引擎时登录并安装：
   ```bash
   semgrep login
   semgrep install-semgrep-pro
   semgrep scan --config "p/php" /path/to/project --pro
   ```
   先在登录前后各跑一次 `p/php`，确认规则数从 16 变为 45（含 29 Pro），并记录账户状态，避免把未登录结果当最终结论。
5. 结果落盘并去色：
   ```bash
   semgrep scan --config "p/php" /path/to/project --no-force-color --dataflow-traces \
     | sed 's/\x1B\[[0-9;]*[mK]//g' > result.txt
   ```
6. VSCode：安装 semgrep 插件，把 `Semgrep: Path` 设为 semgrep 可执行文件、`Semgrep > Scan: Configuration` 指向本地规则目录，Problem 窗口切换树视图按规则名分组查看。
7. 云平台（可选）：目录 `git init` 后 `semgrep ci` 扫描并上传，在 Semgrep Cloud Platform 查看 502 条 findings 等聚合结果；开启 Pro Engine 开关（Settings → Products）后重跑获得跨文件分析结果。

## PoC

```bash
# 离线规则库扫描
semgrep --config /mnt/share/Tools/web/code_audit/semgrep-rules/php /mnt/share/project/ctf_archives/test/baijiacms

# Registry 集合（会触发 metrics）
semgrep --config "p/phpcs-security-audit" /mnt/share/project/ctf_archives/test/baijiacms

# 登录前后规则数对比 + Pro 引擎
semgrep scan --config "p/php" <target>          # 未登录：16 rules
semgrep login && semgrep install-semgrep-pro
semgrep scan --config "p/php" <target> --pro    # 登录：45 rules, 29 Pro

# 输出脱色
semgrep scan --config <rules> <target> --no-force-color --dataflow-traces \
  | sed 's/\x1B\[[0-9;]*[mK]//g' > result.txt
```

离线扫描的典型输出（PHP 项目，57 条规则）中可看到 `php.lang.security.exec-use`（`system('convert'.$quality_command...)` 命令注入候选）、`weak-crypto`（md5 用法）等规则名与文件行号，可作为人工复核入口。

## 变体与关联

- 变体：用 Semgrep Playground 在线调试规则，再落到本地规则库；用 `semgrep publish` 把自研规则提交到 Registry。
- 变体：把 Semgrep 结果导出 SARIF，再交给 LLM/人工复核压误报，见 [[code-analysis-vuln-discovery-sarif-sast-llm-alert-triage]]。
- 关联：[[code-analysis-static-codeql-database-download-github-api-local-query]]（CodeQL 的数据库获取与本地定向查询，另一种定向审计路径）、[[code-analysis-sast-rips-source-sink-taint-scan]]、[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]（同为 source/sink 初筛，Semgrep 更轻量但污点能力弱）。
- 边界：Semgrep 污点分析能力有限，危险函数匹配规则误报多、漏报也不少；Pro 引擎按官方说明只对 Java/JS 完整扫描生效，其他语言效果不稳定；未登录 `--pro` 行为随版本变化；离线规则库需与 semgrep 版本匹配并自行更新。

## 检测与防御

- 审计流程：扫描器结论只作候选，人工复核每一处 source→sink 的数据流与可达性；记录所用规则集版本、登录状态与规则条数，避免低召回被误认为“无漏洞”。
- 合规/隐私：敏感代码库使用本地规则目录并显式 `--metrics off`；避免在未授权项目上执行会拉取 Registry 或 `semgrep ci` 上传结果的操作；检查企业代理/出网策略，防止源码片段随 metrics 外发。
- 防守方视角：把 Semgrep 类 SAST 接入 CI 时固定规则版本、做误报基线与阻断阈值管理，避免软失败（soft-fail）或忽略配置导致扫描形同虚设（参见 CI 配置绕过类卡片）；对高风险项目定期更新规则集并做人工复核。
