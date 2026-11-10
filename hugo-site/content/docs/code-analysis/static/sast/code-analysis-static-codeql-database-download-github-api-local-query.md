---
id: code-analysis-static-codeql-database-download-github-api-local-query
title: 用 GitHub code-scanning API 直接下载开源项目的 CodeQL 数据库，本地跑自定义查询做定向代码审计
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: codeql-database-fetch-github-api-custom-query
tags:
- codeql
- sast
- code-audit
- github-api
- gh-cli
- supply-chain
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W7
  verified_at: '2026-11-09T01:52:59+08:00'
  notes: '已对照原文核对；gh api /repos/<owner>/<repo>/code-scanning/codeql/databases 列表命令、-H ''Accept: application/zip'' 下载命令、返回字段（id/name/language/size/commit_oid）与正文示例查询一致；本次核对未读取图片，codeql database analyze 的本地跑法与 commit_oid 版本一致性属通用补充（原文未演示），未验证'
url: /docs/code-analysis/static/sast/code-analysis-static-codeql-database-download-github-api-local-query/
draft: false
kb_aliases:
- 下载 CodeQL 数据库
- code-scanning 数据库泄露
- gh api codeql databases
- 本地跑 CodeQL 查询
- 开源项目定向审计
---

## 一句话结论

GitHub 的 code scanning 会把为公开仓库构建好的 CodeQL 数据库挂在仓库的 code-scanning API 上：只要该仓库启用了 CodeQL 扫描，用 `gh api /repos/<owner>/<repo>/code-scanning/codeql/databases` 就能看到数据库列表，再加 `-H 'Accept: application/zip'` 把几 GB 的预构建数据库直接下载到本地——不用自己编译项目、不用配环境，就能用自定义 CodeQL 查询对目标开源代码做定向数据流搜索，或先用它定位组件里可疑的 Controller→危险方法调用链。

## 原理

- **CodeQL 数据库是什么**：CodeQL 把源码解析成关系型数据库（代码的 AST、符号表、调用图、数据流事实都存在表里），查询语言在其上做污点追踪。正常流程要先用 CodeQL CLI 为项目建库（对 Java/Maven 项目往往要能成功编译），成本高。
- **GitHub 已经替你建好了**：仓库启用 code scanning（默认 CodeQL 工作流）后，每次扫描产生的数据库会被托管，并通过 REST API `GET /repos/{owner}/{repo}/code-scanning/codeql/databases` 列出，含 `id`、`name`、`language`、`size`、`commit_oid`。这说明数据库对应的是**某个具体 commit**，审计结论要绑定该 commit。
- **拿到的是不是最新代码**：`commit_oid` 决定数据库内容；若想审计最新版本，需要确认该 oid 与目标分支一致，否则结论要按旧版本评估（开源组件漏洞挖掘里这一步很关键，否则会报已修复的问题或漏掉新引入的代码）。
- **本地查询的价值**：拉下来后用 `codeql database analyze`/VS Code CodeQL 插件跑自定义 `.ql`，可以按业务特征精确定向（例如「所有名字含 Controller 的类 → 调用了 localInstall/exec/反序列化入口」），比通读源码快得多；也是拿公开项目练 SAST 规则、验证查询质量的低成本方式。
- **授权边界**：只能下载自己有权访问的仓库（公开仓库人人可下，私有仓库需 token 且有权限）。这是 GitHub 的既有功能，不是绕过，但拿它批量下载他人代码做分析要注意许可证与合规。

## 触发条件

- 目标开源仓库启用了 GitHub code scanning（CodeQL），且数据库仍被保留（有 retention 策略，过旧的可能已被清理）。
- 本地具备 `gh` CLI（已登录，公开仓库匿名也可）与 CodeQL CLI（分析阶段需要，下载阶段不需要）。
- 需要审计的语言与 API 返回的 `language` 匹配（`java`/`javascript`/`python`/`cpp`/`csharp`/`go`/`ruby` 等）。
- 数据库对应的 commit 与你要审计的版本一致或已知差异。

## 利用步骤

1. 列出可用数据库：
   ```bash
   gh api /repos/<owner>/<repo>/code-scanning/codeql/databases
   ```
   记录返回中目标语言的 `name`/`language`/`commit_oid`/`size`。
2. 按语言下载（`Accept: application/zip` 才会返回二进制）：
   ```bash
   gh api /repos/<owner>/<repo>/code-scanning/codeql/databases/<language> \
     -H 'Accept: application/zip' > database.zip
   ```
3. 解压得到 CodeQL 数据库目录（含 `db-java/` 等），用 CodeQL CLI 校验并查询：
   ```bash
   codeql database analyze db-java query.ql --format=sarif-latest --output=result.sarif
   ```
4. 编写定向查询（示例：找出名字含 `Controller` 的类里直接调用了名字含 `localInstall` 的方法）：
   ```ql
   import java

   class SourceController extends Method {
     SourceController() { getQualifiedName().regexpMatch(".+Controller.+") }
   }
   class SinkMethod extends Callable {
     SinkMethod() { getACallee().getName().regexpMatch(".*localInstall.*") }
   }

   from SourceController source, SinkMethod sink
   where source.calls(sink)
   select source, source.getQualifiedName(), sink, sink.getQualifiedName()
   ```
5. 依据结果回到源码定位具体调用点，判断参数是否用户可控、有无前置鉴权；数据流结论用 CodeQL 的污点查询（`TaintTracking`）复核，避免只看调用关系造成误报。
6. 命中后按常规代码审计节奏读过滤器配置、路由与部署文件，确认可达性。

## PoC

```bash
# 1) 列出可用数据库（示例仓库）
gh api /repos/craftcms/cms/code-scanning/codeql/databases

# 2) 下载指定语言的预构建数据库
gh api /repos/craftcms/cms/code-scanning/codeql/databases/javascript \
  -H 'Accept: application/zip' > /tmp/test-database.zip

# 3) 解压后用 CodeQL CLI 跑自定义查询
unzip /tmp/test-database.zip -d /tmp/db
codeql database analyze /tmp/db/<db-dir> controller-sink.ql --format=sarif-latest --output=out.sarif
```

返回体形如（节选字段）：`id`、`name`（`database.zip`）、`language`、`size`（示例约 90MB）、`commit_oid`、`created_at`。

## 变体与关联

- **变体（拿不到数据库时）**：直接 `git clone` 源码 + 本地 `codeql database create`（Java 需可编译）、或用 `semgrep`/`joern` 做同类定向搜索；私有仓库需带 token 且受权限限制。
- **变体（只看调用关系不够）**：用 CodeQL 内置 `security-extended` 套件先跑一遍，再针对命中项写自定义查询；或用 `codeql database print-baseline` 之类做版本对比。
- **关联**：`code-analysis/vuln-discovery` 下源码审计入口卡（从路由/过滤器/Controller 切入的通法）、`code-analysis/static/sast` 下 SAST 规则与误报治理卡；`pentest/recon` 下 GitHub 仓库/CI 情报收集卡（同属「公开仓库暴露构建产物」的思路）。
- 边界：仓库未启用 code scanning、数据库因 retention 过期被清理、或目标版本与 `commit_oid` 不一致时结论失效；下载只得到「代码事实」而非可运行的构建产物，仍需读源码确认可达性。

## 检测与防御

- 检测（作为仓库维护方）：审计 GitHub 上的 code-scanning 数据库下载记录（企业版有 audit log）；确认是否有私有仓库意外公开、或私有仓库的数据库被低权限成员批量拉取。
- 防御：对含敏感逻辑的仓库关闭公开 code scanning 或改用自建 runner 并限制产物保留；私有仓库收紧成员权限与 token scope；对 fork/公开镜像评估代码泄露面；开源项目本身无法阻止他人下载数据库，但可以在许可证与安全策略中声明。
