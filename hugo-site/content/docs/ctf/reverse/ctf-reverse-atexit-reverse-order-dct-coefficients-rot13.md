---
id: ctf-reverse-atexit-reverse-order-dct-coefficients-rot13
title: 主函数为空、逻辑藏在 atexit/全局析构：按注册逆序还原 rot13 + DCT 校验管线并反变换
type: scenario
domain: ctf
path: ctf/reverse
technique: atexit-reverse-order-dct-rot13-inversion
tags:
- ctf
- reverse
- atexit
- global-constructor
- dct
- idct
- rot13
- static-initialization
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V273
  verified_at: '2026-11-08T01:02:36+08:00'
  notes: 已对照原文『你这主函数保真么』段核对：main 空壳、tcf_*/_GLOBAL__sub_I 与 atexit 逆序、Test 长度检查、Test2 rot13、tcf_3 DCT、check 浮点数组、IDCT+rot13 与 DASCTF{Wh0_1s*Ma1n*@nd_FunnY_Dct} 均一致。已修正卡片 caveat：原文 check 数组仅 29 项为换行/截断，实测按此 IDCT 输出乱码，不能复现 flag，需从二进制 .data 重新提取完整数组；已把原『输出长度大于 flag』的错误表述改为按长度不符排查截断/padding。
url: /docs/ctf/reverse/ctf-reverse-atexit-reverse-order-dct-coefficients-rot13/
draft: false
kb_aliases:
- 你这主函数保真么
- atexit 逆序执行
- 全局析构函数
- DCT 系数校验
- 逆离散余弦变换
- rot13 反变换
---

## 一句话结论

程序 `main` 看起来几乎为空，输入检查却分散在 `_GLOBAL__sub_I_*`、`tcf_*` 等全局构造/析构函数里；`atexit`/`__cxa_atexit` 注册的处理函数在程序退出时按注册顺序的**逆序**执行，实际管线是“读入并检查长度 → rot13 → DCT → 与常量数组比较”。把常量数组做逆 DCT、四舍五入为字符、再做一次 rot13（自逆）即可恢复输入。

## 原理

- **全局构造/析构与 atexit 的顺序**：C++ 全局对象构造、GNU `__attribute__((constructor))` 以及显式 `atexit`/`__cxa_atexit` 注册的函数会在程序启动/退出阶段执行。`atexit` 的语义是后注册先执行（LIFO）；C++ 全局析构也按构造的逆序运行。逆向时如果只盯着 `main`，会漏掉这些“藏在生命周期钩子里”的逻辑。
- **本类题的结构**：函数列表出现 `_GLOBAL__sub_I_flag`、`tcf_0`、`tcf_2`、`tcf_3` 这类编译器生成的初始化/析构桩；`Test::Test` 负责读入和长度检查，`tcf_2` 里是比较，`Test2::Test2` 是 rot13，`tcf_3` 里是 DCT。`main` 只是打印提示/触发退出，真正的校验在退出阶段按逆序串起来。
- **DCT 的可逆性**：DCT-II 把长度 N 的向量 `x` 变换为 `X_k = Σ_n x_n·cos(π/N·(n+1/2)·k)`（不同归一化写法等价）；逆变换为 `x_n = Σ_k C_k·X_k·cos(π·k·(2n+1)/(2N))`，其中 `C_0=√(1/N)`、`C_k=√(2/N)`。题目把输入字符转成数值向量后做 DCT，再与常量数组比较；因此对常量数组做 IDCT 即可回到 rot13 后的字符码。
- **rot13 自逆**：rot13 是对字母做 13 位循环移位，连续应用两次回到原文；解密与加密是同一操作。
- **为什么成立**：变换链是确定且可逆的，唯一难点是“执行顺序”被隐藏。识别出 atexit 逆序后，按相反顺序应用逆变换即可。

## 触发条件

- 逆向目标为 C/C++ 二进制（常见 32 位、无壳），`main` 逻辑异常简单或只有提示/输入。
- 函数列表出现 `_GLOBAL__sub_I_*`、`tcf_*`、`__cxa_atexit`、`atexit`、`.init_array`/`.fini_array` 等生命周期相关符号。
- 输入长度检查、比较、加密/编码函数分散在全局构造/析构中；常量数组为浮点数（DCT 系数）或与输入等长的字节数组。
- 程序运行结束后才出现“good/bad”或校验结果，或在退出时崩溃/输出。

## 利用步骤

1. 运行程序，记录提示、输入长度要求和输出；确认 `main` 是否只是壳。
2. 在 IDA/Ghidra 中查看函数窗口与交叉引用，重点找 `_GLOBAL__sub_I_*`、`tcf_*`、`atexit`、`__cxa_atexit`；确定每个函数的注册顺序。
3. 按“退出时逆序执行”还原管线：例如注册顺序为 A、B、C、D，实际退出执行 D、C、B、A；把读入/长度检查、rot13、DCT、比较分别归位。
4. 提取比较用的常量数组（通常在 `.data`/`.rodata`，可能是 `double`/`float`），确认长度 N。
5. 对常量数组做 IDCT：按目标二进制的归一化方式实现；`round()` 成整数后映射为字符（可打印范围 32..126）。
6. 对得到的字符串再做一次 rot13，得到原始输入/flag；若结果仍有噪声，检查 DCT 的缩放因子、是否漏做/多做了一次 rot13、以及数组是否包含填充项。
7. 用重新执行 DCT/rot13 的方式正向验证结果与常量数组一致。

## PoC

```python
import numpy as np

def idct(coeffs):
    N = len(coeffs)
    out = np.zeros(N)
    for n in range(N):
        s = 0.0
        for k in range(N):
            ck = (1.0 / np.sqrt(N)) if k == 0 else np.sqrt(2.0 / N)
            s += ck * coeffs[k] * np.cos(np.pi * k * (2.0 * n + 1) / (2.0 * N))
        out[n] = s
    return out

def rot13(s):
    return "".join(
        chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if 'a' <= c <= 'z'
        else chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if 'A' <= c <= 'Z'
        else c for c in s
    )

# 从二进制 .data/.rodata 提取的检查数组（示例；需按目标实际数组替换）
check = [513.355, -37.7986, 8.7316, -10.7832, -1.3097, -20.5779, 6.9864,
         15.9422, 21.4138, 29.4754, -2.77161, -6.58794, -4.22332, -7.20,
         -4.38138, -19.3898, 18.3453, 6.88259, -14.7652, 14.6102, 24.74,
         -9.75476, 12.2424, 13.4343, -34.9307, -35.735, -20.0848, 39.68,
         26.8296]

vec = idct(check)
s = "".join(chr(int(round(v))) for v in vec if 32 <= int(round(v)) <= 126)
print(rot13(s))
```

```text
# 该题目标结果示例：
# DASCTF{Wh0_1s*Ma1n*@nd_FunnY_Dct}
# 注意：文章中的系数数组存在换行/截断（此处仅 29 项，直接运行上面的 check 数组
# 得到的是乱码，不能复现该 flag），实际长度与数值需从二进制 .data 重新提取；
# 若 IDCT 输出长度与 flag 不符，优先检查数组是否被截断或含 padding。
```

## 变体与关联

- **生命周期钩子变体**：`__attribute__((constructor))`/`destructor`、`.init_array`/`.fini_array`、`atexit`、`__cxa_atexit`、全局对象构造/析构；执行顺序可能是注册顺序、逆序或按优先级。
- **变换变体**：DCT/DFT/Wavelet、AES/XTEA、rot13/凯撒/仿射、线性代数矩阵乘法；只要可逆，按管线逆序求解。
- **隐藏方式变体**：比较函数可能被拆成多个 `tcf_*`、常量数组可能被加密/混淆、`main` 可能被故意写成死代码；需要结合 xref 和动态调试（在 `exit`/`atexit` 处下断点）。
- **关联卡片**：[[ctf-reverse-onnx-dct-frequency-trigger]]（DCT 频域触发器的构造方向）、[[ctf-reverse-obfusheader-dynamic-memcmp-rand-xor-nibble-swap]]（动态 memcmp 定位校验）、[[ctf-reverse-6502-reversible-op-stream-inversion]]（可逆指令流反向执行）。
- **边界**：若比较前有不可逆哈希/随机盐、或 DCT 前还有未知编码，单靠 IDCT 不能恢复；若数组被截断/损坏，需要从二进制重新提取。

## 检测与防御

- **CTF/逆向视角**：不要默认 `main` 就是全部逻辑；先查看 init/fini 数组、atexit 注册、全局构造/析构，并在 `exit` 处动态断点观察执行顺序。
- **开发视角**：不要用全局析构/atexit 承载安全校验或密钥处理；这类逻辑难以审计且依赖未定义的顺序假设。
- **检测信号**：二进制中 `main` 极小但存在多个 `tcf_*`/`_GLOBAL__sub_I_*` 与浮点常量数组；程序退出时才输出校验结果；`.fini_array` 中有可疑函数指针。
- **分析技巧**：用 `readelf -d`/`objdump -s -j .init_array -j .fini_array` 导出函数指针，结合 IDA 的 `atexit` 交叉引用还原注册顺序。
