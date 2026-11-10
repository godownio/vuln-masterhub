---
id: web-java-component-jetty-uriutil-canonicalpath-double-slash-bypass
title: Jetty URIUtil.canonicalPath 双斜杠绕过：//..//..// 让 canonical 长度≥2 绕过 doDotsSlash 拒绝，canonicalPath 返回非 null 而调用方仍用原始 subPath 穿越
type: scenario
domain: web
path: web/java/component
technique: jetty-uriutil-canonicalpath-double-slash-bypass
tags:
- java
- jetty
- path-traversal
- uri-normalization
- canonicalpath
- bypass
- webappcontext
- context-handler
cve:
- CVE-2024-4956
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V381-fix
  verified_at: '2026-11-09T08:32:21+08:00'
  notes: V381 按原文截图 Jetty 9.4.53 doDotsSlash 代码与 Python 复刻指出：canonicalPath('//..//..//..//etc/passwd') 返回的是非 null 但已消解 .. 的规范化串（约 //etc/passwd/），并非『仍含 .. 的路径』；真正问题是 ContextHandler.addPath 仅把 canonicalPath(subPath)!=null 当布尔校验、随后用原始 subPath 构造 PathResource。已修正标题/一句话结论/原理第4点/『为什么是通用缺陷』/边界/步骤5/PoC 注释：明确 canonicalPath 返回值已消解 ..，原始 subPath 保留 ..；删除无原文依据的『现代 Jetty 已修复』。触发条件/PoC/环境与 Nexus 产品卡关联不变。
url: /docs/web/java/component/web-java-component-jetty-uriutil-canonicalpath-double-slash-bypass/
draft: false
kb_aliases:
- Jetty canonicalPath 绕过
- doDotsSlash 绕过
- 双斜杠路径穿越
- //..// 绕过
- URIUtil 规范化缺陷
- CVE-2024-4956 根因
---

## 一句话结论

Jetty 的 `URIUtil.canonicalPath` 在处理 `..` 段时用 `canonical` 串长度做“是否越出根目录”的拒绝判断：普通 `/../../..` 因 canonical 只有 `/`（长度 1）被 `doDotsSlash` 判非法返回 `null`；但把路径写成 `//..//..//..` 时，第一个 `..` 之前的 `//` 让 canonical 长度达到 2，后续 `dots==2` 分支不再命中 `length() < 2` 的拒绝条件，只做删斜杠/截断，函数返回非 `null` 的规范化串（`..` 在该串内已被消解，如 `//etc/passwd/`）；真正的问题在于调用方（`ContextHandler.addPath`）只把 `canonicalPath(subPath) != null` 当布尔校验，随后仍用原始 `subPath` 构造 `PathResource`，原始串里的 `..` 因此保留并拼出越过 `resourceBase` 的文件 URI。

## 原理

- **两段扫描**：`canonicalPath(path)` 先顺序扫描到第一个 `.`，把其前面的部分写入 `canonical`；再逐字符处理 `.`/`/`，用 `dots` 计数连续点号，遇到 `/` 时调用 `doDotsSlash(canonical, dots)`。
- **拒绝条件**：`doDotsSlash` 在 `dots == 2` 时执行 `if (canonical.length() < 2) return true;`，返回 `true` 会让 `canonicalPath` 返回 `null`，上层 `addPath` 随即抛出 `MalformedURLException`（表现为 HTTP 400）。
- **普通穿越被拦**：`/../../../../etc/passwd` 处理第一个 `..` 时 `canonical` 只有 `/`（长度 1），`length() < 2` 成立，直接拒绝——这是“看似安全”的来源。
- **双斜杠改变长度**：路径以 `//..` 开头时，第一个 `.` 之前的部分是 `//`，`canonical` 长度为 2；处理 `..` 时拒绝条件不成立，`doDotsSlash` 只执行 `setLength(len-1)` 和 `setLength(lastIndexOf("/") + 1)` 做删斜杠/截断，不再拒绝。路径中 `..` 之后继续出现 `//` 时，`dots==0` 分支又会把 `/` 追加回 `canonical`，使后续 `..` 仍满足长度条件。最终函数返回的是非 `null` 的规范化串（按 9.4.53 代码模拟，`//..//..//..//etc/passwd` → `//etc/passwd/`，`..` 已在该串内被消解），而不是 `null`；保留 `..` 的是调用方随后使用的原始 `subPath`。
- **调用方拼接**：`ContextHandler.addPath(subPath)` 只检查 `canonicalPath(subPath) != null`，随后用原始 `subPath` 构造 `new PathResource(parent, subPath)`；`PathResource` 调用 `URIUtil.addPath(parent.uri, childPath)` 得到形如 `file:/opt/sonatype/nexus/public//../../../../etc/passwd` 的 URI。文件系统解析时 `//` 折叠、`..` 正常生效，最终访问到 `resourceBase` 之外的文件。
- **为什么是通用缺陷**：问题出在调用方对 `canonicalPath` 结果的使用方式——只把它当布尔校验，却继续用原始 `subPath` 拼接，而不是某个业务参数解析错误；任何把用户可控路径传给 `ContextHandler`/`WebAppContext` 的 `addPath`/`getResource` 且未做二次白名单校验的 Java 应用，在同一 Jetty 逻辑下都可能被 `//..` 形式绕过（canonicalPath 返回非 null 即放行）。
- **边界**：该行为依赖具体 Jetty 版本（原文仅验证 9.4.53，其他版本需按实际代码确认）；利用还要求应用的 resourceBase 是一个真实目录且最终文件对进程可读；前置代理/浏览器若提前折叠 `..` 或拒绝连续斜杠，请求到不了漏洞点。

## 触发条件

- 目标 Java 应用使用存在该 `canonicalPath`/`doDotsSlash` 逻辑的 Jetty（原文环境中 Nexus 3.68.0 内置 Jetty 9.4.53.v20231009），并把用户可控路径传入 `ContextHandler.addPath` 或 `WebAppContext.getResource`。
- 请求路径能保留 `//..` 形式（需 `curl --path-as-is` 或 URL 编码，避免客户端/代理规范化）。
- 最终目标文件对 Jetty 进程可读，且响应会把内容返回（静态资源下载、文件预览等 sink）。

## 利用步骤

1. 确认目标使用 Jetty 且版本未修复；观察 `Server: Jetty (...)` 响应头或应用依赖。
2. 先发普通 `GET /../../../../etc/passwd`，确认返回 400（说明路径进入了 canonicalPath 校验）。
3. 改发 `GET //..//..//..//..//..//..//etc/passwd`（或编码形式），使用 `curl --path-as-is` 保留双斜杠。
4. 若响应 200 且返回文件内容，说明 canonicalPath 被绕过、resourceBase 被穿越；按 sink 读取配置、密钥、系统文件。
5. 在单元层面验证可调用 `URIUtil.canonicalPath("/..")` 与 `URIUtil.canonicalPath("//..//..")` 对比返回值（前者 `null`；后者为非 `null` 的规范化串，`..` 已在返回值内被消解，但调用方仍使用原始 `subPath` 拼接）。

## PoC

```bash
# 普通穿越被 canonicalPath 拒绝（400）
curl --path-as-is -i 'http://target:8081/../../../../etc/passwd'

# 双斜杠绕过（200，返回文件内容）
curl --path-as-is -i 'http://target:8081//..//..//..//..//..//..//etc/passwd'
```

```java
// 逻辑验证（需目标 Jetty 版本）
URIUtil.canonicalPath("/../../etc/passwd");        // null
URIUtil.canonicalPath("//..//..//..//etc/passwd"); // 非 null（规范化串如 //etc/passwd/）；原始 subPath 中的 .. 仍被调用方使用
```

原文在 Nexus 3.68.0（Jetty 9.4.53）上以该形式成功读取 `/etc/passwd`；本卡未复现。

## 变体与关联

- **产品化利用**：Nexus Repository 3 的 `WebResourceServlet` 把 `pathInfo` 传入 `addPath`，是本文的实际 CVE 场景（已有 CVE-2024-4956 产品卡，包含受影响版本 3.0–3.68.0 与编码斜杠 PoC）。
- **变体**：重复斜杠数量、`..` 前后斜杠配比可调整；`%2f`/`%2e%2e` 编码可绕过简单关键字过滤。
- **同类归一化缺陷**：Spring `cleanPath` 绕过（CVE-2018-1271）等“重复斜杠改变 `..` 抵消层数”的家族问题。
- **修复**：升级 Jetty/Nexus；业务侧对用户路径先规范化并校验最终路径必须位于 base 目录内，不要只依赖 `canonicalPath` 非空。

## 检测与防御

- **升级**：使用修复后的 Jetty 版本，或升级 Nexus Repository 3 到 3.68.1+。
- **输入校验**：拒绝包含连续斜杠、`.`/`..` 段的路径；对路径做 `Path.normalize()` 后校验 `startsWith(baseDir)`，而不是仅检查 `canonicalPath` 是否非空。
- **WAF/代理**：检测 `//..`、`%2F%2F`、多重编码点段；在代理层先规范化 URL 再路由。
- **日志与监控**：关注静态资源路径中出现连续斜杠和 `..` 的 200 响应，尤其是返回系统文件内容的请求。
