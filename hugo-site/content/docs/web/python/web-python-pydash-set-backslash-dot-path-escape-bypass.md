---
id: web-python-pydash-set-backslash-dot-path-escape-bypass
title: pydash.set_ 反斜杠转义绕过「_.」过滤：__class__\\.__init__ 既避开字符串检查又按点分割进入 dunder 链
type: scenario
domain: web
path: web/python
technique: pydash-set-backslash-dot-filter-bypass
tags:
- python
- pydash
- path-parsing
- filter-bypass
- attribute-pollution
- dunder
- waf-bypass
- prototype-pollution
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V381
  verified_at: '2026-11-09T08:13:50+08:00'
  notes: 已对照原文与27张图核对：pydash 5.1.2 RE_PATH_KEY_DELIM 偶数字节反斜杠+点作分隔符、单反斜杠+点保留字面点，__class__\.__init__ 在JSON解码后为双反斜杠故原始串不含 '_.' 且仍被按点分割；与既有已验证 Sanic 完整链卡中的 RE_PATH_KEY_DELIM 说明一致；payload（含 __mp_main__\.static 单反斜杠保留字面点）与原文图23/24成功请求一致。pydash==5.1.2 为挑战环境版本非受影响区间，affected_versions 保持空；与 Sanic 完整链/pydash 通用污染卡为不同层次，非重复（dedup 仅 self，trigram 0.137）
url: /docs/web/python/web-python-pydash-set-backslash-dot-path-escape-bypass/
draft: false
kb_aliases:
- pydash 绕过滤
- to_path_tokens 反斜杠
- __. 过滤绕过
- RE_PATH_KEY_DELIM
- pydash 5.1.2 路径解析
- 点号转义绕过
---

## 一句话结论

pydash 5.1.2 的路径解析把「前面不是转义反斜杠的点」当作分隔符，并把成对反斜杠消耗掉；因此把路径写成 `__class__\\.__init__\\.__globals__` 时，原始字符串里 `_` 后面紧跟的是反斜杠而不是点，不含子串 `_.`，可以绕过 `'_.' not in key` 这类朴素过滤；而 pydash 解析时仍把 `\\.` 当分隔符，得到 `__class__`、`__init__`、`__globals__` 等路径段，继续沿 dunder 链到达模块全局并污染任意属性。

## 原理

- **朴素过滤的假设**：很多代码用 `if '_.' not in key` 或 `'__' not in key` 阻止 `__class__.__init__.__globals__` 这类利用，假设 dunder 段之间一定以裸点连接。
- **pydash 的分隔符规则**：`to_path_tokens` 用正则 `RE_PATH_KEY_DELIM` 切分路径，分隔符是「前面为偶数个反斜杠的点」，匹配时反斜杠被消耗；因此：
  - `\.`（单个反斜杠 + 点）表示键名中的**字面点**，不分割；
  - `\\.`（两个反斜杠 + 点）表示**分隔符**，分割并得到不含反斜杠的段名。
- **绕过成立的原因**：字符串 `__class__\\.__init__` 的字节序列是 `_ _ c l a s s _ _ \ \ . _ _ i n i t ...`，子串 `_.`（下划线紧接点）不出现，过滤通过；pydash 分割后却得到 `['__class__', '__init__']`，dunder 属性照常可访问。单反斜杠形式 `__mp_main__\.static` 还能把含字面点的键（如 Sanic 路由名 `__mp_main__.static`）作为一个整体段保留。
- **JSON 层转义**：若入口是 JSON，payload 中的两个反斜杠在 JSON 文本里要写成四个（`\\\\`），经 JSON 解码后才是 pydash 看到的 `\\`。
- **危害**：绕过过滤后，`pydash.set_(obj, path, value)` 可沿 `__class__`/`__init__`/`__globals__` 写到类属性、模块全局、框架对象（如 Flask 配置、Sanic 静态 handler），把属性污染升级为目录遍历、任意文件读取或 RCE；具体影响取决于可达对象链。
- **边界**：pydash 6.x 起默认拒绝 dunder 路径段（视版本与配置），需实测；若过滤在 URL/JSON 解码前对原始字符串做严格白名单（只允许字母数字和下划线），反斜杠会被直接拒绝，绕过失效。

## 触发条件

- 应用使用 pydash `set_`（或同类路径写入函数）并把用户可控的路径字符串传入，且 pydash 版本存在 dunder 路径暴露。
- 过滤逻辑是子串检查（如 `'_.' not in key`、`'__' not in key`）而不是严格字符白名单。
- 输入经过 JSON/表单解析后能保留反斜杠（JSON 中使用 `\\` 转义，表单需正确编码）。
- 目标对象链上存在危险属性（框架单例、配置、全局变量等）。

## 利用步骤

1. 确认 pydash 版本与过滤逻辑（源码/报错/依赖文件），判断是 `'_.' not in key` 还是其它检查。
2. 在本地用相同版本验证分词：
   ```python
   import pydash
   print(pydash.to_path_tokens("__class__\\\\.__init__\\\\.__globals__"))
   # ['__class__', '__init__', '__globals__']
   ```
3. 构造绕过分隔：把每个 dunder 之间的 `.` 写成 `\\.`（JSON 中 `\\\\`），确保原始字符串不含 `_.`。
4. 通过入口提交 `key` 与 `value`，先写一个无害路径验证成功，再沿目标对象链写到危险属性。
5. 访问对应功能验证效果（配置变更、目录遍历、文件读取、命令执行等）。

## PoC

```python
import pydash

key = "__class__\\\\.__init__\\\\.__globals__"   # pydash 看到 __class__\\.__init__\\.__globals__
print('_.' in key)                                 # False：绕过 '_.' not in key 检查
print(pydash.to_path_tokens(key))                  # ['__class__', '__init__', '__globals__']

class Pollute:
    pass

obj = Pollute()
pydash.set_(obj, key + "\\\\.__file__", "/etc/passwd")  # 具体目标视应用全局变量而定
print(obj.__class__.__init__.__globals__.get("__file__"))
```

原文在 Sanic 靶场用该形式绕过 `'_.' not in key`，把 `__class__\\.__init__\\.__globals__\\.app...` 写入框架单例；本卡未单独复现。

## 变体与关联

- **单反斜杠保留字面点**：`__mp_main__\.static` 作为一个路径段，用于命中带字面点的路由名字典键。
- **反斜杠数量奇偶**：奇数个反斜杠时点被转义为字面点，偶数个时点作为分隔符；可据此构造更复杂的过滤绕过。
- **同类过滤**：`'.' not in key` 可用 `\.` 让点以转义形式出现；`'__' not in key` 可尝试 Unicode/编码或其它分隔变体（视解析器）。
- **关联卡**：Sanic 静态 handler 关键词污染（完整利用链）、pydash.set_ 属性污染（通用影响面）。

## 检测与防御

- **输入校验**：不要把用户可控路径传给 `pydash.set_`；如必须使用，采用严格字段白名单（只允许 `[a-zA-Z0-9_]`），在 JSON 解码后、pydash 解析前统一拒绝反斜杠与点号。
- **升级依赖**：使用修复 dunder 路径的 pydash 版本（>=6.x），并确认项目未关闭相关保护。
- **代码审计**：搜索 `pydash.set_`/`set_` 调用与 `'_.'`、`'__'` 子串过滤，标记所有“子串检查 + 用户可控路径”的组合。
- **WAF/日志**：检测请求体中出现 `\\\\`、`\\.` 形式的 dunder 路径与 `__class__`/`__globals__` 关键字。
