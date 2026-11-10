---
id: code-analysis-sast-ast-chain-depth-escalation-triage
title: AST 调用链深度递增扫描（depth≤3→4）+ 按 sink 分级复现：把链清单变成可验证漏洞清单
type: scenario
domain: code-analysis
path: code-analysis/static/sast
technique: ast-callchain-depth-escalation-and-sink-triage
tags:
- code-audit
- sast
- ast
- callgraph
- php
- source-sink
- triage
- chain-depth
cve: []
severity: low
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3
  verified_at: '2026-11-08T00:29:02+08:00'
  notes: '已对照原文与 10 张图核对：图01 depth<=3 链清单、图02 depth=4 链清单与卡内「深度递增召回」一致；图03 分链结论 #1 任意文件读取成功、#4 利用冒号截断但写入内容为空、#6/#8 文件读写失败、#9 判断文件是否存在再写入，与卡内委托台账一致。已修正 PoC 台账：原文对 #2/#3/#5/#6/#7/#8 只写「失败」未给原因，卡片原先自行补了「固定后缀」「目标函数被禁用」「内网不可达」等具体原因，属原文未证实的推断，已改为「失败（原因原文未给）」并保留编号与 Action 链；同时把 #9 的落点改为「写入成功但不在 Web 根、访问不到」。本卡为审计方法卡(confidence=medium、无 CVE、不含可利用性断言)，其 PoC 是通用 BFS 骨架代码而非文中命令，可复用性成立。未验证点：未运行该骨架代码、未验证 depth 递增在本项目内的实际召回率。'
url: /docs/code-analysis/static/sast/code-analysis-sast-ast-chain-depth-escalation-triage/
draft: false
kb_aliases:
- 调用链深度递增
- 深度3/深度4 链对比
- 自建 AST 链查找
- 链清单分级复现
- Controller 到 sink 链枚举
- 恶意函数调用链检测
---

## 一句话结论

用 AST 从 Controller 动作出发向危险函数做**深度受限**的调用链搜索时，先从 depth≤3 跑一遍拿到「一眼可判」的短链，再把深度提到 4（或更高）补出跨过一层帮助类/工具类的长链；随后按 sink 类型（文件读 / 文件写 / 命令执行 / SSRF）逐条黑盒复现并记录失败原因，最终得到的是「可验证漏洞清单」而不是一份需要人工逐条看的链清单——深度递增负责召回，分级复现负责去伪。

## 原理

- 深度限制的取舍：depth≤3 的链通常是 `Action → 直接方法 → sink`，最容易复核但也最容易漏；实际代码里 sink 往往隔着一层 `XxxHelp`/`XxxToolkit`/`MockController` 之类的中间类，不提高深度就搜不到（原文把深度从 3 提到 4 后立刻多出一批 `Action → Help → sink` 的链）。
- 链只是「可能」：AST 只能证明调用关系存在，无法证明参数可控、无法证明前置条件（登录、CSRF token、nonce、`phar.readonly` 之类运行时开关）满足。因此每条链都必须回到 HTTP 层验证一次，并显式记录失败原因（接口 404/鉴权失败/写入路径不在 Web 目录/命令执行被禁用/SSRF 出网受限）。
- 按 sink 分类复现的效率远高于按链逐条试：同一天里把「文件读」类链集中验证（通常 1~2 条能打通，其余因编码/协议限制失败）、再验证「文件写」类（常见失败原因是固定后缀、目标目录不在 Web 根）、最后验证「命令执行」与「SSRF」。同类链共享前置条件，一次环境确认可复用于多条。
- 多链组合要单独判定：原文中「链 4（写固定后缀文件）+ 链 9（写可控内容）」看似可拼成 getshell，实测截断后写不进内容、可控写入又落在 Web 目录之外，组合仍不通——这说明**多链组合必须整体验证**，不能因为两条链各自「可写」就推断组合可用。
- 输出形态决定可用性：把结果按「链编号 → Action(类) → 中间方法 → sink(函数)」逐行打印，并标注每条链的验证结论（成功/失败原因），比只给调用图更适合直接分配给复现；xlsx/清单按 sink 分 sheet 也一样。
- 该方法的边界：它不解决「参数是否可控」这一核心问题（那是污点分析/人工确认的活）；对动态派发（`call_user_func`、`$this->$method()`、反射）只能给出候选，需人工补边。

## 触发条件

- 目标为 PHP/Java 等有明确「控制器动作 → 业务方法 → 危险函数」结构的 MVC 框架项目，且能拿到源码。
- 具备能解析项目的 AST 工具（自建解析器、phply、nikic/php-parser、tabby、CodeQL 等任一）。
- 已定义一份 sink 列表（`file_get_contents`、`file_put_contents`、`unlink`、`copy`、`curl_exec`、`call_user_func`、`system`/`exec` 等）。
- 有可复现的运行环境（安装好的实例 + 可登录账号 + 必要 token），用于逐链验证。

## 利用步骤

1. 定义 source（类名含 `Controller` 且为动作方法）与 sink（危险函数名集合），把 sink 按「读/写/执行/网络」分组。
2. 以 depth=3 跑第一轮，输出全部链；对照源码把明显不可控参数（常量、配置项）的链先划掉。
3. 把 depth 提到 4（必要时 5），重新跑并只保留「新增」的链；这些通常跨过一层 Help/Toolkit。
4. 按 sink 分组逐条复现：先用合法请求打基线（返回 200 且行为符合预期），再替换为探测载荷（读 `/etc/passwd`、写测试文件、`sleep` 型命令、内网地址）。
5. 为每条链记录结论：`成功` / `失败：鉴权` / `失败：路径不在 Web 根` / `失败：写入内容为空` / `失败：运行时开关（如 phar.readonly）`。
6. 对「单链不通但组合看似可行」的情况（如一条建文件、一条写内容），把组合作为一条新链整体验证，不要按单链结论外推。
7. 把最终清单按 sink 分组成表格交付，剩余未验证链标注「待人工确认参数可控性」。

## PoC

```python
# 深度受限的链搜索骨架（概念示例：从 Controller 动作向 sink 做 DFS）
from collections import deque

def find_chains(callgraph, entries, sinks, max_depth=4):
    out = []
    for src in entries:
        q = deque([(src, [src])])
        while q:
            node, path = q.popleft()
            if len(path) - 1 > max_depth:
                continue
            if node in sinks:
                out.append(path)
                continue
            for callee in callgraph.get(node, []):
                if callee in path:      # 避免环
                    continue
                q.append((callee, path + [callee]))
    return out

for d in (3, 4):
    chains = find_chains(callgraph, entries, sinks, max_depth=d)
    print(f"depth={d}: {len(chains)} chains")
    for c in chains:
        print(" -> ".join(c))
```

```text
# 输出形态（对应原文 depth<=3 与 depth=4 两轮）
createFromUrlAction(ArticleController) (CALLS) -> file_get_contents(Php)        # 任意文件读取 成功
paymentAction(FinanceSettingController) (CALLS) -> updateWeixinMpFile(...) (CALLS) -> file_put_contents(Php)  # 冒号截断 .txt 后缀后写不进内容
userCenterAction(UserSettingController) (CALLS) -> file_put_contents(Php)       # 需目标文件已存在；写入成功但落点不在 Web 根
```

```text
# 台账（每条链一行结论；仅 #1 与 #4/#9 的结论是原文写明的，其余只写「失败」，原文未给原因）
#1 文件读      成功                       createFromUrlAction(ArticleController) -> file_get_contents
#2 文件上传    失败（原因原文未给）          cropImgAction(FileController) -> cropImages -> copy
#3 命令执行    失败（原因原文未给）          updateItemHomeworkTaskAction -> sometimesToMessage -> call_user_func
#4 文件写      失败：用 : 截断后缀，截断后内容写不进   paymentAction(FinanceSettingController) -> updateWeixinMpFile -> file_put_contents
#5 SSRF        失败（原因原文未给）          applyForSmsAction(EduCloudController) -> post(MockController) -> curl_exec
#6 文件读取    失败（原因原文未给）          avatarFetchPartnerAction(SettingsController) -> cropImages -> copy
#7 文件上传    失败（原因原文未给）          studentsExportDatasAction -> addFileTitle(ExportHelp) -> file_put_contents
#8 文件上传    失败（原因原文未给）          cropImgAction(FileController) -> cropImages -> copy
#9 文件写      写入成功但落点不在 Web 根、访问不到   userCenterAction(UserSettingController) -> file_put_contents
```

## 变体与关联

- 变体：把 AST 结果落到图数据库（Neo4j）后用 `apoc.algo.allSimplePaths` 求最大深度路径，适合大规模项目与增量查询；见 `[[code-analysis-sast-phply-neo4j-php-callchain-sink-query]]`。
- 变体：Java 项目用 tabby 生成 CPG 再按 Controller→sink 查链；见 `[[code-analysis-sast-tabby-neo4j-controller-sink-callchain]]`。
- 变体：为减少误报，在搜索阶段就把 sink 分组成「必查/抽查」，并对同名函数按 namespace/class 绑定，避免把内置函数与项目自定义同名函数混为一谈。
- 关联：`[[code-analysis-sast-phply-neo4j-php-callchain-sink-query]]` 侧重「建图 + Cypher 查询」的工程化；本卡侧重「深度递增召回 + 按 sink 分级复现」的流程与判据。`[[code-analysis-dynamic-debugging-ast-extract-mock-sink-fuzz]]` 是链定位后的动态验证方式。
- 边界：AST 只静态可见；动态派发、字符串拼接函数名、框架魔术方法（`__call`）会断链，需要人工补边或运行时插桩；纯工具操作（安装解析器、导出 xlsx）不构成原语。

## 检测与防御

- 该卡为审计方法，防御侧对应：把危险 sink 收敛到统一封装层（框架已有的 `$request->query` + ORM/文件抽象），减少「Action 直连危险函数」的链路数量。
- 加固：CI 中加入 sink 名单的静态门禁（新增代码若在 Controller→sink 深度 ≤2 内出现危险函数即告警）；对 `file_get_contents`/`file_put_contents` 参数做协议与路径白名单校验。
- 检测：代码评审记录里「链清单」应附带每条链的运行时验证结论，避免把未验证链当成漏洞上报。
