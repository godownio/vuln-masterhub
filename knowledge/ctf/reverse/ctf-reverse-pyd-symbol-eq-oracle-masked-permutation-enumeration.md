---
id: ctf-reverse-pyd-symbol-eq-oracle-masked-permutation-enumeration
title: Cython pyd 校验器盲测：替换模块函数返回值包装成「比较即打印」的 Symbol 对象，从 __eq__ 日志读出每段期望值，再枚举被掩码吃掉的高位补出 8 位 hex 输入
type: scenario
domain: ctf
path: ctf/reverse
technique: pyd-symbol-eq-comparison-oracle-masked-bit-enumeration
aliases:
- rand0m.pyd 逆向
- Symbol 类劫持 __eq__ 记录比较
- 比较即打印 oracle
- 掩码位枚举 2**6
- hex 段逐段爆破
- Cython pyd check 函数逆向
tags:
- ctf
- reverse
- python
- pyd
- cython
- monkey-patch
- oracle
- brute-force
- hex
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4B
  verified_at: '2026-11-08T21:48:52+08:00'
  notes: 已对照原文核对；本次核对未读取图片（4 张图为 IDA 反编译与爆破输出截图，正文已给出等价代码）；卡片对原文的补充限于「掩码常量 0xFA3AFFFF / 被掩位 idx=[1,3,4,5,9,11] / 2**6 枚举」等原文文字已给的内容；原文作者自述爆破脚本有 bug，卡片 confidence 保持 medium；未在本机复跑
---

## 一句话结论

当 flag 校验在 Cython 编译的 `rand0m.pyd` 里、算法又只露一半时，不必硬逆：把模块导出的变换函数 `rand0m(x)` 包一层，返回值换成自定义 `Symbol` 对象（其 `__eq__` 会打印被比较的数值），再调用 `check(flag)` —— 日志里立刻出现"每 8 个 hex 字符的输入段 vs 期望结果"的对应关系；对算法中信息被 `&` 掩掉的部分，只枚举掩码覆盖的那些位（示例 6 位 → 64 次），用未掩码的那一路结果做筛选，即可拼回完整输入。

## 原理

- **Python 层可插桩**：`pyd`/`so` 扩展模块的模块级属性（`module.check`、`module.rand0m`）是普通 Python 对象，`import` 后可以整体替换。包装函数保留原实现，只在返回值上做手脚，校验逻辑本身照旧执行。
- **比较即泄漏**：校验器最后必然把"计算值"与"常量期望值"对比。返回自定义对象并实现 `__eq__`，Python 走的是 `left.__eq__(right)`，于是右边那个常量期望值会作为参数传进来，被打印出来 —— 等价于一个免费的比较 oracle。
- **分段结构**：示例里 `check` 把输入按 8 个 hex 字符切成 4 段，每段调 `rand0m(x)` 得到两个 32 位结果，只用第二个参与比较。日志因此天然对齐"第几段 → 期望值"。
- **半掩码算法可枚举**：`t4 = (x << 4) & 0xFA3AFFFF`、`t5 = x >> 28`、`t6 = t4 | t5` 这种写法，`&` 会把若干位清零（示例掩掉 6 位），但被掩掉的位只影响第二个结果；第一个结果 `t9 = f(x) % ...` 保留了全部信息，用来做筛选条件。
- **为什么能解出**：对每个段，把掩码对应的 6 个位按 0/1 枚举（2^6 = 64 种），逐个喂给 `rand0m`，凡第一个结果等于日志里记录的期望值，就说明该候选与原始输入在"影响输出的所有位"上一致；再取其中还原到 flag 字符集（`flag{...}`/base64 字符）唯一可读的那一个。
- **探针技巧**：用一个全 1 输入（`0xFFFFFFFF`）先跑一遍，`&` 结果里为 0 的位就是掩码为 0 的位置，一次就把掩码常量测出来。

## 触发条件

- 目标是 Python 扩展（`pyd`/`.so`，Cython、C 扩展均可），能从 Python 侧 `import` 并调用其导出函数。
- 校验函数在 Python 层可被替换（模块属性可赋值），且比较由 Python 对象协议完成（`==` 走 `__eq__`），不是 C 里直接 `memcmp`。
- 算法存在"部分位被掩码、其余位可验证"的结构；否则枚举空间退化为全量爆破。

## 利用步骤

1. `help(module)` / `dir()` 摸清导出接口（`check`、`rand0m`、`__test__`）。
2. 用全 1 探针输入测掩码常量：`rand0m("FFFFFFFF")` 输出中为 0 的位即被 `&` 清零的位。
3. 写 `Symbol` 类：`__eq__` 里 `print(self.name, other)`，构造时把数值格式化成 hex 字符串存进 `name`。
4. 包装 `rand0m`：调用原函数拿到 `(a, b)`，返回 `(Symbol(a), Symbol(b))`；包装 `check` 只加日志。
5. 用一个全 `0` 或全 `a` 的假 flag 触发 `check`，从日志取"段序号 → 期望值"表。
6. 对每段枚举掩码位组合（2^k），用未掩码那一路的结果与期望值比对；命中的候选再按可打印字符集过滤，拼回完整 flag。

## PoC

```python
import rand0m

class Symbol:
    def __init__(self, name):
        self.name = name
    def __eq__(self, other):
        if isinstance(other, Symbol):
            return self.name == other.name
        print(f"cmp {self.name} vs {other:08x}")   # 期望值被打印出来
        return self.name == other

_orig_rand = rand0m.rand0m
_orig_check = rand0m.check

def my_rand(x):
    a, b = _orig_rand(x)
    return (Symbol(f"{a:x}"), Symbol(f"{b:x}"))

def my_check(flag):
    print("check", flag)
    return _orig_check(flag)

rand0m.rand0m = my_rand
rand0m.check = my_check
rand0m.check("1234567890abcdef1234567890abcdef")
```

```python
# 掩码位枚举：掩掉 6 位 -> 64 次
final2 = [0x98d24b3a, 0xe0f1db77, 0xadf38403, 0xd8499bb6]   # 从 __eq__ 日志抄出的期望值
flag   = [0x812287f3, 0xd4a30f74, 0x8023a126, 0x78810880]   # 从 __eq__ 日志抄出的输入侧骨架
idx = [1, 3, 4, 5, 9, 11]                                    # 被掩码吃掉的位号
for z in range(4):
    for i in range(2 ** 6):
        bits = format(i, "06b")
        test = flag[z]
        for j in range(6):
            test |= int(bits[j]) << (23 - idx[j])
        if rand0m.rand0m(f"{test:08x}")[0] == final2[z]:
            print(z, bits, f"{test:08x}")
```

## 变体与关联

- 比较入口换成 `bytes.__eq__`、`str.startswith`、`hmac.compare_digest`、`hashlib` 结果比对时同理；C 层 `memcmp` 不经过 Python 钩子，需要 gdb/Frida 断点观察。
- 若无 `__eq__` 可用（校验在 C 里直接比），退化用"返回长度/异常类型/耗时"作侧信道。
- 算法完全黑盒时把本方法与逐字节枚举（每段独立、可并行）结合：先测掩码再枚举，比全量 16^n 小几个数量级。
- 相关：Cython pyd 的包装函数与实现函数分离、常量槽交叉引用等静态还原手法可先定位 `check` 里的比较点，再用本动态 oracle 定值。

## 检测与防御

- 检测：CTF 之外的意义有限；若业务把授权校验放在可被 `import` 的 Python 扩展里，攻击者可在宿主进程替换模块函数并观察比较结果 —— 敏感比较应在不可插桩的边界（独立进程/服务端）完成。
- 防御：校验用 C 层常量时间比较且不向调用方暴露中间值；`pyd` 只暴露"通过/不通过"布尔，不返回可被 Python 层包装的中间结果；对扩展模块做完整性校验。
