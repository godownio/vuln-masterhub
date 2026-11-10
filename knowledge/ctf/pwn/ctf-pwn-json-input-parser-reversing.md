---
id: ctf-pwn-json-input-parser-reversing
title: Pwn 题 JSON 交互逆向：从 null/true/false、引号与 {[ 分支及 ,/} 闭合校验识别 JSON 输入并构造合法请求
type: scenario
domain: ctf
path: ctf/pwn
technique: json-input-parser-reversing
aliases:
- pwn 中 json 的逆向
- json 交互识别
- 手写 json 解析器逆向
- scanf 4095s json
- ezheap json
tags:
- ctf
- pwn
- reverse
- json
- parser
- protocol
- input-format
- scanf
- heap-noise
cve: []
severity: medium
confidence: high
status: draft
created: '2026-11-08'
updated: '2026-11-08'
---

## 一句话结论

当 pwn 题的主循环用 `__isoc99_scanf("%4095s", buf)` 读入一整段非空白字符串、再交给一个手写解析函数时，只要在该函数里认出 `null`/`true`/`false` 字面量比较、`"` 字符串分支、`[`/`{` 递归分支以及 `,` 与 `}`/`]` 的闭合校验，就可以判定交互层是 JSON；按紧凑格式 `{"choice":"new","index":1,"length":20,"message":"hello"}` 构造输入即可穿过交互层（二进制 payload 直接放进 `message` 字符串值），而解析过程自身的 malloc/realloc/free 会给堆布局引入噪声，堆利用时必须一并计算。

## 原理

- **入口特征**：主循环是 `printf("Please input:"); __isoc99_scanf("%4095s", v13); res = sub_34A7(v13); if (!res) ...`。`%4095s` 只读到空白字符为止，因此合法的 JSON 必须写成不含空格/换行的紧凑形式；解析函数返回 0 时菜单重新提示，返回非 0 才执行对应功能。
- **JSON 值解析的识别点**：`sub_391B` 依次用 `strncmp(ptr, "null", 4)`、`strncmp(ptr, "false", 5)`、`strncmp(ptr, "true", 4)` 匹配字面量，分别设置类型标记（4/1/2，true 还额外置一个布尔字段）；随后 `'"'` 分支进入字符串解析，`'-'` 与 `'0'..'9'` 分支进入数字解析，`'['` 调用数组解析函数 `sub_3E4A`，`'{'` 调用对象解析函数 `sub_42BB`。这些分支与 JSON 文法一一对应，是“输入是 JSON”的直接证据。
- **对象/数组的闭合校验**：对象解析 `sub_42BB` 先限制元素计数（原文比较 `> 0x3E7`），循环读取键、冒号与值，再用 `*(a2+16) >= *(a2+8)`（越界）以及当前字节是否 `,`、`}`、`]` 判断分隔与闭合；解析失败返回 0 让主循环重来。看到这种“逗号分隔 + 右括号闭合”的状态机即可确认格式。
- **字符串值直接承载原始字节**：解析器对字符串做 `strlen + 1` 后复制/重分配到堆块（`sub_3244` → `sub_3296`）。手写解析器通常不像标准 JSON 库那样处理 `\uXXXX` 转义，而是把两个引号之间的字节原样收下，因此攻击者可以把二进制 payload 直接拼在 `"message":"` 之后，只要避开会提前结束字符串或对象的字节（`"`、`}` 等）。
- **解析器的堆噪声**：每个请求进入解析函数后都会调用 `my_malloc`/`my_realloc`/`my_free` 构造临时结构（原文反编译中可见 `my_free`、`my_realloc` 与解析子函数的分配）。这些临时块会改变堆的 chunk 布局，纯粹按菜单 add/delete 计算的偏移会错位；原文在泄 libc 前专门用一次 `add(0x60, '')` 吸收/定位这部分噪声，再做后续利用。

## 触发条件

- Linux x64 CTF pwn 题，交互层为“提示 → `scanf("%4095s")`（或 fgets/read 整行）→ 解析函数 → 分发到 new/modify/rm/view 等功能”。
- 反汇编中能定位到 JSON 关键字与分隔符比较：`null`/`true`/`false`、`"`、`[`、`{`、`,`、`}`、`]`。
- 题目本身存在可利用的内存漏洞（UAF、edit 无长度校验、堆溢出等）；本卡只解决“如何与 JSON 交互层对话并让 payload 通过”。

## 利用步骤

1. 定位主循环：`printf("Please input:")` → `scanf("%4095s", buf)` → `sub_XXX(buf)`，记录返回值如何控制菜单。
2. 跟入解析函数，搜索 `null`/`true`/`false` 字符串常量与 `'['`/`'{'` 分支；确认存在 `,` 分隔与 `}`/`]` 闭合校验后判定为 JSON。
3. 用最小对象探测字段名与功能：发送 `{"choice":"new","index":1,"length":20,"message":"hello"}`（必须紧凑、无空格），观察菜单是否执行 new。
4. 逐个确认字段：`choice` 对应 new/modify/rm/view；`index` 对应槽位；`length` 对应写入长度；`message` 对应内容。原文 `delete`/`edit` 的索引检查是 `a1 <= 6`（7 个槽位），`edit` 的 `memcpy(chunklist[a1], src, len)` 不校验 len 与原块大小。
5. 构造攻击请求：`b'{"choice":"new","index":1,"length":' + str(n).encode() + b',"message":"' + payload + b'"}'`。payload 里若需要 `"`、`}` 等会破坏 JSON 的字节，改用数字字段（length/index）承载或分多次 write 写满（原文正是用无长度限制的 modify 反复写已释放块）。
6. 在堆布局计算中给解析器临时分配留余量：先发几条无害 JSON 让解析器完成一次完整的分配/释放循环，再用小块（原文 0x60）吸收噪声，之后才做 unsorted bin 泄漏等精确布局操作。

## PoC

交互辅助函数（字段名按原文 ezheap 的 new/modify/rm/view）：

```python
from pwn import *

p = process('./pwn')
menu = b'Please input:'

def add(size, cont):
    payload = b'{"choice":"new","index":1,"length":' + str(size).encode()
    payload += b',"message":"' + cont + b'"}'
    p.sendlineafter(menu, payload)

def edit(idx, length, cont):
    payload = b'{"choice":"modify","index":' + str(idx).encode()
    payload += b',"length":' + str(length).encode() + b',"message":"' + cont + b'"}'
    p.sendlineafter(menu, payload)

def delete(idx):
    payload = b'{"choice":"rm","index":' + str(idx).encode()
    payload += b',"length":20,"message":"1"}'
    p.sendlineafter(menu, payload)

def show(idx):
    payload = b'{"choice":"view","index":' + str(idx).encode()
    payload += b',"length":20,"message":"1"}'
    p.sendlineafter(menu, payload)
```

最小验证：`add(0x20, b'hello')` 后菜单应执行 new 而不是重新提示；说明 JSON 被解析通过。

## 变体与关联

- 变体：解析器可能把 `%s` 换成 `fgets`/`read`，此时 JSON 可带空格；如果 `message` 中不能出现某些字节，可把有意义的数值放在 `index`/`length` 等数字字段，或分成多次 modify 写入。
- 变体：有的题目 JSON 值解析只支持 `"` 字符串和数字，字符串中的转义会破坏原始字节；可先测 `\"`、`\\` 的行为再决定 payload 编码。
- 关联：[[ctf-pwn-interpreter-serialization-expansion-heap-overflow]] 同属“解析器交互 + 堆利用”的组合，但那边是序列化字段膨胀造成堆溢出；[[ctf-pwn-hexfloat-strtoull-parser-differential]] 讲同一输入被两个解析器读出不同语义。
- 关联：交互层确认后再按题目漏洞选择堆链，例如 [[binary-pwn-heap-glibc231-tcache-key-clear-repeated-free-freehook]]。

## 检测与防御

- 对 CTF 题目本身：识别交互协议是逆向步骤，无“防御”可言；出题方可对 `message` 做转义/长度校验，避免原始字节直通。
- 对真实产品：不要把手写 JSON 解析器当作安全边界；必须做长度上限、字符串转义、分配失败与递归深度检查，并优先使用成熟 JSON 库。
- 检测特征：服务端出现 `%4095s` 一类定长读入后紧跟手写 `{`/`[` 状态机；输入不以 `{` 开头或闭合不匹配时被拒绝。
