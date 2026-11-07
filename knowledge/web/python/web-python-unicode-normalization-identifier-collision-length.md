---
id: web-python-unicode-normalization-identifier-collision-length
title: Python 标识符 NFKC 归一化：方法名折叠覆盖与兼容字符压缩长度
type: scenario
domain: web
path: web/python
technique: python-unicode-identifier-normalization
aliases:
- Python 标识符归一化冲突
- tesᵗ 与 test 同名
- Unicode 兼容字符压缩长度
- Ⅷ 绕过长度限制
- NFKC 方法名覆盖
- Python 斜体字符标识符
severity: medium
confidence: high
status: verified
created: '2026-11-04'
updated: '2026-11-05'
tags:
- python
- unicode
- nfkc
- identifier
- bypass
- eval
- waf-bypass
cve: []
verification:
  verified_by: verifier-V6
  verified_at: '2026-11-05T00:36:57+08:00'
  notes: 已对照原文与7张图核对：dir(A) 中 tesᵗ 归一化为 test、重复定义后者覆盖（A.test()/A.tesᵗ() 均输出2）、task_Ⅷ() 长度8/NFKC后11、通过长度检查后 exec 输出 OK，均与原文一致；字符串字面量不被折叠的边界也正确。未验证点：未在本机执行PoC；原文未给版本区间，未设versions。
---

## 一句话结论

Python 3 在编译期按 NFKC 归一化**标识符**，所以源代码里的 `tesᵗ` 与 `test` 会落到同一个名字上：先定义的方法可被后定义的变体字符方法静默覆盖；同时，`Ⅷ` 这类兼容字符能用一个字符表示 `VIII` 四个字符，使长度限制检查与实际语义长度不一致。字符串字面量不参与这种归一化，这是该手法的重要边界。

## 原理

- Python 3 遵循 PEP 3131，对标识符做 NFKC（Unicode 兼容合成）归一化后再作为名字表 key。数学斜体、粗体、全角、上标、下标、连字等字符，NFKC 后会折叠成对应 ASCII 标识符。
- 因此 `def tesᵗ()` 在类字典中注册的 key 是 `test`；`dir(A)` 只显示 `test`，逐字符打印也是 `0x74 0x65 0x73 0x74`。若同一作用域先定义 `test`、再定义 `tesᵗ`，后者覆盖前者；调用 `A.test()` 与 `A.tesᵗ()` 都执行后者（原文实测两者都输出 2）。
- 该特性可用于：
  - 在允许注入代码/定义方法的场景（插件、模板、动态 exec）中覆盖安全校验方法或业务方法；
  - 绕过基于 ASCII 方法名/关键字匹配的 WAF（变体字符在 UTF-8 字节层面与 ASCII 不同）；
  - 制造同名冲突，让审计者看到的源码与实际绑定不一致。
- **边界一**：字符串字面量不做 NFKC/NFC 以外语义的兼容折叠。`"ʰᵉ𝓵𝓵ℴ"` 作为字符串内容时 NFD/NFC 保持原样，NFKD/NFKC 才展开成 `hello`；而标识符在编译期已按 NFKC 归一化。原文用 `prinᵗ(1)` 能执行、`"ʰᵉ𝓵𝓵ℴ..."` 仍按原字符串输出验证了这一点。
- **边界二**：关键字（`class`、`def`）、语法符号不能被替换；替换只对标识符有效。
- **长度压缩**：`Ⅷ`（U+2167）NFKC 为 `VIII`，一个字符语义上等于四个字符。`task_Ⅷ()` 原文长度 8，NFKC 后 `task_VIII()` 长度 11；若过滤器只检查原文长度 `<= 8`，则通过检查后 `exec` 仍能调用 `task_VIII`。反向的长度膨胀也可用于让过滤器低估/高估内容。
- 攻击能否落地取决于存在“对不可信输入执行代码/定义方法”的入口（exec/eval、模板编译、插件加载），以及过滤器在归一化前的表示上做判断。

## 触发条件

- 存在用户可控的 `eval`/`exec`、动态方法定义或代码生成入口。
- WAF/长度校验基于原始字符串（未做 NFKC 归一化）或只匹配 ASCII 标识符。
- 目标 Python 3（PEP 3131 生效）；不同 Web 框架可能提前归一化/转义，可用字符集合会变化。
- 覆盖场景需要攻击者能在目标命名空间中定义同名方法。

## 利用步骤

1. 确认代码执行/方法定义入口，以及输入是否经过 NFKC 归一化。
2. 选择目标标识符（如 `system`、`exec`、`test`、业务校验方法名）。
3. 用 NFKC 等价的变体字符替换其中部分字符（如 `𝘴𝘺𝘴𝘵𝘦𝘮`、`tesᵗ`），构造 payload。
4. 若存在长度限制，用 `Ⅷ`、`№`、`™` 等“一字符展开多字符”的兼容字符压缩原文长度。
5. 发送并观察：WAF 未命中、执行成功、方法覆盖生效。
6. 注意字符串字面量不会被同样折叠；需要隐藏的字符串内容应使用 `\uXXXX` 转义或其他编码层手法。

## PoC

方法名折叠与覆盖：

```python
class A:
    def test():
        print("original")
    def tesᵗ():          # NFKC 后同样是 "test"
        print("hijacked")

print([n for n in dir(A) if not n.startswith('__')])  # ['test']
A.test()    # hijacked
A.tesᵗ()    # hijacked
```

长度限制绕过：

```python
import unicodedata

def task_VIII():
    print("OK")

payload = "task_Ⅷ()"
print(len(payload))                              # 8
print(len(unicodedata.normalize('NFKC', payload)))  # 11

if len(payload) > 8:
    print("fail")
else:
    exec(payload)                                # 输出 OK
```

标识符变体示例（部分）：`a` → `ᵃ/ａ/𝐚/𝑎/𝒂/𝓪`，`t` → `ᵗ/ｔ/𝐭/𝑡/𝓉`，`0` → `０/𝟎/𝟘/𝟢`，`_` → `＿/﹍/﹏`。原文给出 A–Z、a–z、0–9、下划线的完整可用表。

## 变体与关联

- 通用 WAF 绕过（NFKC 斜体标识符 + Base64/零宽/Latin-1）已有独立卡片；本卡聚焦“标识符折叠/覆盖”与“长度压缩”两个新维度。
- 与 Unicode 规范化相关的另一类问题是同一字符串的多种表示导致比较/去重不一致（NFC vs NFD）。
- Bottle 等框架在 URL 解码时按单个 `%XX` 处理，可用变体字符受限（原文提到 `%aa`/`%ba`），需按框架实测。
- JSON 层的 `\uXXXX` 转义绕过见独立卡片。

## 检测与防御

- 对所有输入先做 NFKC/NFKD 归一化，再执行关键字、长度、语法校验；长度限制应在归一化后计算。
- 禁止对不可信输入使用 `eval`/`exec`；使用 AST 白名单或隔离沙箱，只允许明确的表达式子集。
- 拒绝代码执行上下文中的非 ASCII 标识符（或只允许 `[A-Za-z_][A-Za-z0-9_]*`）。
- 代码审计关注 `exec`/`eval`/`compile` 与动态 `setattr`/`def` 生成；检测变体字符（U+1D400–U+1D7FF、全角区、上标/下标区）。
- 对方法覆盖风险做命名空间隔离，避免用户代码与安全校验方法共享同一作用域。
