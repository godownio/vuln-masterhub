---
id: web-generic-file-inclusion-view-file-directory-oracle-hidden-dir-enum
title: 文件查看接口对目录与不存在路径返回不同提示：把“是不是目录”变成枚举 oracle，扫出 .hidden 等隐藏目录再读文件
type: scenario
domain: web
path: web/generic/file-inclusion
technique: file-view-directory-existence-oracle-hidden-path-enum
tags:
- file-read
- directory-enumeration
- oracle
- hidden-directory
- information-disclosure
- ctf
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W2
  verified_at: '2026-11-08T18:37:24+08:00'
  notes: 已对照原文核对；本次核对未读取图片；view-file 接口、参数名 file、file=1 返回 Access denied、file=log/error.log 读到日志、file=log 回显「是一个目录」、file=.hidden 与 .hidden/flag.txt 均与原文一致，目录穿越失败也按原文写入边界。未验证点：靶机已下线，PoC 未复跑；批量脚本为归纳写法
url: /docs/web/generic/file-inclusion/web-generic-file-inclusion-view-file-directory-oracle-hidden-dir-enum/
draft: false
kb_aliases:
- 目录 oracle
- 是目录 回显差异
- view-file 枚举
- 隐藏目录 .hidden
- 文件读取接口目录探测
---

## 一句话结论

一个只能按路径读文件的接口（`?file=log/error.log`）看似无害：目录穿越被拦、也读不到系统文件。但如果它在“路径是目录”和“路径不存在”时给出不同提示（前者说这是一个目录，后者统一 `Access denied`），这个差异就是一个稳定的存在性 oracle——先判出哪些名字是目录，再逐层拼路径，就能把不对外链接的隐藏目录（如 `.hidden`）和其中的文件全枚举出来，最终读到本不该暴露的文件。

## 原理

- **提示差异来自不同的错误分支**：读文件前通常先 `File.exists()` / `isDirectory()` 判断。目录分支走“这是目录，请指定文件”的提示，不存在分支走统一拒绝，两条分支的文案/状态码/长度不同，就泄露了一个比特的信息。
- **单比特足够做枚举**：把字典里的名字逐个拼进 `file=` 参数，按返回文案分类，就能把“存在的目录/文件”从“不存在”里筛出来；命中目录后再把该目录名做前缀继续拼（`log/`、`.hidden/`），形成逐层下降的目录爬取。
- **为什么会漏出隐藏目录**：隐藏靠的是“没在任何页面里链接”，目录本身仍在磁盘上且 Web 进程可读；一旦存在性可判定，隐蔽性假设立刻失效。
- **与目录穿越的区别**：这里不需要 `../`。穿越被拦不影响 oracle——枚举发生在 Web 根之内的相对路径上，读到的也是根内文件（如 `.hidden/flag.txt`）；危害来自“本不该可达的路径可达”，而不是“跳出根目录”。
- **为什么比盲扫可靠**：普通目录扫描靠状态码 200/404 判断，动态路由常把所有路径都返回 200；而这里判据是业务自己产生的语义化提示，误报极低。

## 触发条件

- 存在按用户提供的路径读取文件的接口（参数名可从页面推断，如 `file`、`path`、`name`）。
- 实现对“目录”与“不存在”返回可区分的响应（文案、状态码、长度、耗时任一维度）。
- 目标路径在 Web 根内、进程可读；目录穿越可以完全不可用。

## 利用步骤

1. 从报错信息里找线索：登录失败提示、异常页堆栈、日志内容常直接写出服务端相对路径（如 `log/error.log`），据此确认“路径是相对 Web 根”的。
2. 定位读文件接口：报错里出现的功能名/路由（如 `view-file`）直接访问，观察是否需要参数、参数名叫什么（常见 `file`）。
3. 建立基线：请求一个确定不存在的名字（`?file=1`）记录基线响应；再请求已知存在的文件（`?file=log/error.log`）记录成功响应。
4. 请求一个已知存在的目录（`?file=log`）：如果返回“这是一个目录”类提示，就确认 oracle 成立。
5. 用目录/文件名字典批量请求，按响应归类：命中目录的追加 `/` 继续下钻，命中文件的直接读取；重点字典要含 `.hidden`、`.git`、`backup`、`tmp`、`logs`、`admin` 等。
6. 对枚举出的隐藏目录继续下钻并猜常见文件名（`flag.txt`、`config.php`、`.env`、`backup.zip`），拿到敏感文件。
7. 若目录提示不明显，改看响应长度/状态码差异，或用大小写、尾斜杠（`log` 与 `log/`）对比制造差异。

## PoC

```http
GET /view-file?file=1 HTTP/1.1
Host: target
# 基线：不存在 → Access denied

GET /view-file?file=log/error.log HTTP/1.1
Host: target
# 命中文件：返回日志内容

GET /view-file?file=log HTTP/1.1
Host: target
# 命中目录：提示这是一个目录（不是 Access denied）→ oracle 成立

GET /view-file?file=.hidden HTTP/1.1
Host: target
# 命中隐藏目录

GET /view-file?file=.hidden/flag.txt HTTP/1.1
Host: target
# 读取隐藏目录内文件
```

```bash
# 批量分类（按响应文案差异筛出目录）
for n in $(cat names.txt); do
  r=$(curl -s -o /tmp/o -w '%{http_code}' "http://target/view-file?file=$n")
  if ! grep -q 'Access denied' /tmp/o; then echo "[hit] $n ($r)"; fi
done
```

## 变体与关联

- **判据变体**：状态码（403 vs 404 vs 200）、`Content-Length`、响应时间（目录判断更快）、错误码文案、是否返回 `Content-Disposition`。
- **参数变体**：参数名不是 `file` 时，从前端 JS、报错堆栈或接口命名猜（`path`、`fileName`、`filePath`、`src`）；也可直接传空值观察默认行为。
- **与穿越组合**：oracle 找到目录后再试编码穿越（`%2e%2e%2f`、`....//`）扩大范围，见 [[web-generic-file-inclusion-double-encoded-alternating-dotdot-traversal]]。
- **关联**：[[web-generic-file-inclusion-download-param-source-disclosure]]（同类“file 参数原样读取”导致的源码泄露）、[[pentest-recon-ds-store-directory-listing-disclosure]]（另一种隐藏路径发现途径）。
- **边界**：所有分支统一返回同一提示、或读文件前先做白名单目录校验时，oracle 不成立；隐藏目录不在 Web 根内时也只能看到“存在但不可读”。

## 检测与防御

- **修复**：读文件接口不接受任意路径——用 ID 映射到固定文件名，或把请求路径 `normalize()` 后校验仍在白名单目录内；不做“目录/文件”两级语义区分。
- **错误响应统一**：不存在、无权限、是目录一律返回同一状态码与同一文案，且不回显绝对/相对路径；异常页不展示堆栈与内部路径。
- **加固**：敏感文件移出 Web 根；把 `.hidden` 这类目录改成不可预测名字并加真实鉴权；对同一会话的高频 `file=` 探测做频次限制与告警。
- **检测**：访问日志中同一 IP 对同一接口大量不同 `file` 值（尤其是 `.` 开头名字、字典词）的 403/200 混合请求；请求中出现 `../`、`%2e`、尾斜杠变体。
