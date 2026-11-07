---
id: web-generic-xss-justhtml-rawtext-style-serialization-mxss
title: JustHTML Raw-text 元素原样序列化：style 内 </style> 突破导致 mXSS（GHSA-qvc2-mg72-jjhx）
type: scenario
domain: web
path: web/generic/xss
technique: rawtext-literal-serialization-mxss
tags:
- xss
- mxss
- justhtml
- python
- html-sanitizer
- rawtext
- serialization
- style-tag
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: justhtml <= 1.11.0
verification:
  verified_by: verifier-V40
  verified_at: '2026-11-05T06:32:27+08:00'
  notes: 已对照原文与图15/16、22-24及JustHTML复现图核对：_LITERAL_TEXT_SERIALIZATION_ELEMENTS={"script","style"}，_serialize_text_for_parent 对Raw-text子文本直接 return text，不转义；PoC style 节点文本 </style><script>alert('mXSS_Fixed_Again')</script><style> 序列化后图21/19实测弹窗；修复v1.12.0在sanitize增加 _neutralize_rawtext_end_tag_sequences，将 </style 的 < 替换为 &lt;。affected_versions justhtml<=1.11.0 与原文一致。PoC未在本机执行。frontmatter 无 sources/source_url。
url: /docs/web/generic/xss/web-generic-xss-justhtml-rawtext-style-serialization-mxss/
draft: false
kb_aliases:
- JustHTML mXSS
- GHSA-qvc2-mg72-jjhx
- Raw-text 序列化逃逸
- style 标签闭合 mXSS
- AST 序列化语义错位
- 突变型 XSS
---

## 一句话结论

JustHTML `<= 1.11.0` 在序列化时对 `script`/`style` 的子文本节点按 Raw-text 规则原样输出，不转义也不检查闭合标签；若攻击者能控制该文本，写入 `</style><script>alert(1)</script>` 就能在浏览器二次解析时提前结束 Raw-text 上下文，使 script 逃逸为真实节点，形成 mXSS。

## 原理

- HTML 规范把 `script`、`style` 等称为 Raw-text 元素：其中的文本不做 HTML 实体解码，但解析状态机会在遇到匹配的 `</style>`（或 `</script>`）时立即切回普通 HTML 解析。
- JustHTML 的序列化器定义 `_LITERAL_TEXT_SERIALIZATION_ELEMENTS = {"script", "style"}`；`_serialize_text_for_parent` 只要发现父节点名在该集合中，就直接 `return text`，不做 `_escape_text` 的 `&`/`<`/`>` 转义。
- 在内存 AST 视角里，`<style>` 节点下挂的只是一个普通字符串，过滤器认为它不具备“打破标签边界”的能力；但序列化成字符串后会与 `<style>`/`</style>` 拼接成真正的 HTML 字节流。
- 浏览器重新解析时只认字节：遇到文本中的 `</style>` 就结束 Raw-text，随后紧跟的 `<script>` 被当作正常标签解析并执行。内存态与字符串态的语义不一致，即 mutation XSS。
- 关键不是“过滤时漏了 `<script>`”，而是“过滤后的 AST 是安全的，序列化过程把安全语义丢掉了”。

## 触发条件

- 使用 JustHTML `<= 1.11.0`。
- 应用把用户可控字符串作为 `style`/`script` 节点的文本子节点（例如自定义 CSS 预览、动态构造 AST、允许保留 `<style>` 的策略），并调用其序列化输出。
- 序列化结果被拼入页面且未再次 sanitize（如 Jinja `|safe`、直接字符串拼接）。
- 浏览器按正常 Raw-text 规则解析输出。

## 利用步骤

1. 找到把用户输入放进 `style` 或 `script` 节点文本的应用路径，例如“自定义主题 CSS”“公式/样式预览”。
2. 提交同时包含正常 CSS 与闭合序列的载荷：`body{background:gray}</style><script>alert(1)</script><style>`。
3. JustHTML 原样序列化为 `<style>body{background:gray}</style><script>alert(1)</script><style></style>`。
4. 浏览器解析到第一个 `</style>` 时结束样式上下文，`<script>` 成为活动节点并执行。
5. 末尾的 `<style>` 用于吸收序列化器追加的闭合标签，保持结构可控。

## PoC

```python
from justhtml.node import Node
from justhtml import serialize as serialize_mod

style_node = Node(name="style")
style_node.children.append(
    "body { background: gray; } </style><script>alert('mXSS')</script><style>"
)
html = serialize_mod._node_to_html(style_node)
print(html)
# <style>body { background: gray; } </style><script>alert('mXSS')</script><style></style>
```

把 `html` 原样插入页面（例如 Flask 模板中的 `{{ custom_style|safe }}`），浏览器弹窗。原文用 Flask 复现，终端确认序列化输出包含未转义的闭合序列，浏览器确认弹窗。

## 变体与关联

- 同一缺陷适用于 `script` 父节点：文本中的 `</script><img src=x onerror=...>` 可逃逸。
- 其它 Raw-text/RCDATA 元素（`textarea`、`title`）若被序列化器当作明文处理，也可能出现同类突变，但需结合具体解析规则验证。
- 与 [[web-generic-xss-dompurify-mxss-caption-flattening]]、[[web-generic-xss-dompurify-parentnode-clobbering-depth-bypass]] 同属 mXSS：差异在于本卡是序列化器丢失 Raw-text 上下文，而非 DOM 命名空间/节点重排。
- 与 Goldmark 的实体时序错位同属“过滤态 ≠ 浏览器态”，但错位发生在 AST→字符串的序列化阶段。

## 检测与防御

- 升级 JustHTML 到 `1.12.0+`；该版本在 sanitize 阶段加入 `_neutralize_rawtext_end_tag_sequences`，把 `</style`/`</script` 起始的 `<` 替换为 `&lt;`，使浏览器在 Raw-text 内不把它当闭合标签。
- 自行实现时：对进入 `script`/`style` 文本的不可信内容，检测 `</tagname` 后跟 `>`、空白、`/` 等结束边界并中性化；不要仅依赖 HTML 实体转义（Raw-text 内实体不解码，改写 `&lt;` 反而可能失效或改变语义）。
- 输出前用 DOMPurify 等基于浏览器解析器的 sanitizer 做后置兜底；不要信任“已经过 AST 过滤”的字符串。
- 审计：搜索 `parent_name in {"script","style"}` 一类“原样返回”分支，以及直接 `children.append(user_input)` 构造 Raw-text 节点的代码。
- 运行时检测：响应 HTML 中出现 `<style>` 内部含 `</style` 或 `<script>` 的嵌套结构；CSP 作为纵深防御限制内联脚本执行。
