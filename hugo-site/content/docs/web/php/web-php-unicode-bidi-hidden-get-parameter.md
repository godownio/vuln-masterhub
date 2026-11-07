---
id: web-php-unicode-bidi-hidden-get-parameter
title: 源码隐藏参数：Unicode Bidi 控制符构造不可见 GET 参数名
type: scenario
domain: web
path: web/php
technique: unicode-bidi-hidden-get-parameter
tags:
- php
- unicode
- bidi
- hidden-parameter
- source-obfuscation
- waf-bypass
- auth-bypass
- code-review
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V117
  verified_at: '2026-11-06T02:05:36+08:00'
  notes: 已对照原文「仓库中的圈套」核对：源码条件 admin == $_GET['cytcv'] && "bmkfd⁩ncd" == $_GET['⁦fguyfnk⁩kef']；参数名含 U+2066/U+2069、比较值含 U+2069，可见形式分别为 fguyfnkkef 与 bmkfdncd；最终 exp /secret.php?cytcv=admin&%E2%81%A6fguyfnk%E2%81%A9kef=bmkfd%E2%81%A9ncd 与原文一致，本地复算 quote 编码相同。未复跑；无 CVE/版本；frontmatter 无 sources/source_url。
url: /docs/web/php/web-php-unicode-bidi-hidden-get-parameter/
draft: false
kb_aliases:
- Unicode 控制符隐藏参数
- U+2066 U+2069 参数名
- 不可见 GET 参数
- Bidi 字符后门参数
- 源码隐藏条件
---

## 一句话结论

PHP 源码的 GET 参数名和比较值中夹带 Unicode Bidi 控制符（如 U+2066 LEFT-TO-RIGHT ISOLATE、U+2069 POP DIRECTIONAL ISOLATE）时，编辑器/代码审阅看到的字符顺序与真实字节不一致；攻击者按真实码点做百分号编码构造请求，即可命中人工审阅时“看不见”的隐藏参数与比较条件。

## 原理

- Unicode Bidi 控制符属于格式字符（Cf 类），不显示为可见字形，但参与文本方向与渲染；在源码编辑器中可能被隐藏、折叠或改变显示顺序。
- 源码里 `/*⁦⁩*/` 看似空注释，实际包含 U+2066/U+2069；参数名 `⁦fguyfnk⁩kef` 去掉控制符后与普通标识符相同，人工审阅容易误判为 `fguyfnkkef`。
- PHP 的 `$_GET` 键按原始字节匹配；请求参数名必须包含同样的 U+2066/U+2069 才能命中。浏览器/curl 需把控制符做 UTF-8 百分号编码（U+2066 = `%E2%81%A6`，U+2069 = `%E2%81%A9`）。
- 比较值 `bmkfd⁩ncd` 也夹带 U+2069，单纯发送 `bmkfdncd` 不会相等；这类隐藏条件可被用作后门/CTF 陷阱，也可用于绕过只检查可见字符的 WAF。
- 根因是“源码/日志/审计工具的渲染层与 PHP 的字节比较层不一致”，而不是 PHP 解析器漏洞。

## 触发条件

- 目标 PHP 源码中存在不可见 Unicode 控制符（参数名、字符串、注释、比较值）。
- 攻击者能获得/泄露源码（git 泄露、备份、LFI、源码泄露），或通过错误信息推断隐藏字符。
- 隐藏参数参与鉴权/业务判断，且请求可由攻击者构造。
- 应用未对参数名做 Unicode 规范化/控制符过滤；WAF/日志未转义显示控制符。
- 攻击者知道目标使用的控制符码点（可通过 hexdump、Python repr、`encodeURIComponent` 确认）。

## 利用步骤

1. 获取源码片段，用 `xxd`/`hexdump`/Python `repr` 查看不可见字符；定位参数名与比较值中的 U+2066/U+2069、U+202A–U+202E 等。
2. 记录真实码点序列，确认去掉控制符后的“可见名”与真实键的差异。
3. 用 Python/Node 生成百分号编码：`encodeURIComponent("⁦fguyfnk⁩kef")` 或 `quote()`。
4. 构造请求：可见参数照常发送，隐藏参数用编码后的名字与值；注意值中的控制符也要编码。
5. 观察响应差异；若被 WAF 拦截，尝试双重编码、大小写、在值中插入零宽字符等变体。
6. 命中隐藏条件后读取敏感数据/进入管理员分支。

## PoC

```python
from urllib.parse import quote

hidden_key = "⁦fguyfnk⁩kef"
hidden_val = "bmkfd⁩ncd"
url = f"/secret.php?cytcv=admin&{quote(hidden_key, safe='')}={quote(hidden_val, safe='')}"
print(url)
# /secret.php?cytcv=admin&%E2%81%A6fguyfnk%E2%81%A9kef=bmkfd%E2%81%A9ncd
```

```javascript
encodeURIComponent("⁦")   // "%E2%81%A6"
encodeURIComponent("⁩")   // "%E2%81%A9"
```

无真实目标 PoC：原文为 CTF 源码审计题，参数名/值需按实际源码提取；卡内不包含题目 flag。

## 变体与关联

- **控制符类型**：U+202A–U+202E（LRE/RLE/PDF/LRO/RLO）、U+2066–U+2069（LRI/RLI/FSI/PDI）、零宽空格 U+200B、零宽非连接符 U+200C、BOM U+FEFF。
- **同形字符**：西里尔/希腊字母、全角字符、Unicode 规范化差异（NFC/NFD）可让参数名/域名看起来相同但字节不同。
- **隐藏位置**：参数名、比较值、注释、变量名、HTML 属性、日志字段、AI 提示词。
- **关联**：RTL Override 文件名伪装、Unicode 同形 IDN、Unicode 标签字符走私、WAF 规范化差异。

## 检测与防御

- **源码扫描**：CI/代码审计中检测 Cf 类字符（U+200B–U+200F、U+202A–U+202E、U+2060–U+2064、U+2066–U+2069、U+FEFF），对标识符/字符串中的不可见字符告警。
- **输入规范化**：对参数名/值做 Unicode 规范化并拒绝控制字符；WAF 先解码百分号编码再匹配。
- **日志转义**：日志/告警平台把控制符转义为 `\uXXXX`，避免审阅时被隐藏。
- **代码审阅**：用 `xxd`/`cat -A`/IDE 显示不可见字符；对“空注释”“看似普通但比较失败”的代码重点核查。
- **最小权限**：隐藏参数不应作为唯一鉴权条件；敏感分支需服务端强认证与审计。

## 可信度与边界

- 原文为 CTF 题，源码中的 U+2066/U+2069、百分号编码请求与最终命中均有实测输出；攻击链完整。
- 具体参数名/值/文件路径为该题环境；真实源码需重新提取控制符码点。
- 未在真实目标复跑；卡内不包含题目 flag。
