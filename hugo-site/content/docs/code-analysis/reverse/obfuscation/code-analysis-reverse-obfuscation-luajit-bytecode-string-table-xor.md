---
id: code-analysis-reverse-obfuscation-luajit-bytecode-string-table-xor
title: LuaJIT 字节码字符串表去混淆：自定义 Base64 字母表 + 密钥 XOR 循环，断点 dump 明文
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: luajit-bytecode-string-table-custom-base64-xor
tags:
- reverse
- obfuscation
- luajit
- bytecode
- string-decryption
- xor
- base64
- malware-analysis
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V451
  verified_at: '2026-11-10T01:41:15+08:00'
  notes: 已对照原文与49/49图片核对：var_0_19 字符串表由 var_0_18/var_0_17 填充（图27-28）、var_0_20 为替换密钥表（原文/图29）、var_0_22 字符→0-63 映射（如 ["`"]=34，图29）、解码循环 var_0_34+var_0_37*64^(3-var_0_35) 与 %65536/256 取字节（图30-31）、断点写回处 var_0_26[iter_0_3]=var_0_28(var_0_32)（图30，原文第1174行附近）、watch 中可见 Tamper Detected! 等明文（图32/33）均与卡一致。与 ctf-reverse-lua53-bytecode-xor-rc4（Lua5.3+循环异或+RC4）不同：本卡为 LuaJIT/Lua5.1 自定义64字符表+密钥表变换+断点dump，dedup_review 成立。卡内 confidence=medium、明示字母表/辅助函数未完整给出，符合原文。无版本可设。无 sources/source_url/文章ID/URL/长段摘录，路径 code-analysis/reverse/obfuscation 合法。未验证点：解码器 PoC 未运行，位序/密钥未按样本复核。
url: /docs/code-analysis/reverse/obfuscation/code-analysis-reverse-obfuscation-luajit-bytecode-string-table-xor/
draft: false
kb_aliases:
- LuaJIT 字节码反混淆
- Lua 字符串表解密
- 自定义 Base64 字母表
- 字节码断点 dump
- Lua 5.1 字节码分析
- readme.txt 字节码还原
---

## 一句话结论

当 Lua 恶意样本把 Lua 5.1 字节码伪装成文本文件时，静态反编译器往往只能给出“能看但编译不过”的 Lua 伪代码；真正要拿字符串，需要先修好反编译脚本，再定位字节码里的字符串表构造与解密循环——它用一张自定义字母表把字符映射成 0–63 的数值，每 4 个字符累加成 24 位后取字节，再与密钥表做 XOR/算术变换——在解密结果写回表之前（原文约第 1174 行）下断点，直接从 watch 窗口读出明文。

## 原理

- **Lua 5.1 字节码可识别但不等于可读**：文件头 `1B 4C 4A 02` 表明是 Lua 5.1 字节码；unluac 等开源反编译器对定制/混淆字节码的还原结果存在差异，常出现语法错误、缺失局部变量或顺序错乱，需要按报错手工修补后才能重新编译运行。
- **字符串表延迟解密**：字节码启动时先构造 `var_0_19`（字符串表）和 `var_0_20`（替换密钥表）。`var_0_19` 中的元素不是明文，而是用自定义编码保存的密文；`var_0_22` 是字符到 0–63 的映射表（例如 `["`"] = 34` 这类 64 项），相当于一套自定义 Base64 字母表。
- **解码循环的数学结构**：循环逐个取字符 `var_0_37 = var_0_22[char]`，用 `var_0_34 = var_0_34 + var_0_37 * 64^(3 - var_0_35)` 把 4 个 6-bit 值累加成 24 位整数；每凑满 4 个字符，通过 `var_0_23(var_0_34 % 65536 / 256)` 取中间字节，再由 `var_0_21`/`var_0_24`/`var_0_25`/`var_0_27`/`var_0_28` 等辅助函数做 XOR/位移/类型转换，最终写回 `var_0_26[iter]`。循环里插入大量无意义行与恒真/恒假分支，增加人工阅读成本。
- **为什么动态 dump 更快**：无论静态复现的位序、密钥调度是否完全正确，字节码最终都会把解密后的字符串写回表。在赋值语句前下断点，watch `var_0_26` 就能看到逐条解密出的明文（原文观察到 `Tamper Detected!`、`getVerification`、`getDebugPrivilege` 等字符串），比纯静态推导稳定。
- **为什么成立**：Lua 解释器在内存中必然持有明文才能调用 API/比较字符串；断点位于解释执行路径内，不依赖反编译器完全正确；解密循环是确定性的，可重复命中。
- **置信度说明**：原文截图展示了表结构、循环代码与 watch 结果，但未给出完整字母表与全部辅助函数；本卡的算法结构由截图推断，具体位序/密钥需按样本实际代码调整，因此 confidence 标 medium。

## 触发条件

- 拿到 Lua 5.1/LuaJIT 字节码样本（常见伪装为 `.txt`/`.dat` 或嵌入其他文件）；
- 有可用的 Lua 反编译器与调试器（能加载字节码、下断点、查看局部/上值表）；
- 反编译脚本经修补后能运行到解密循环；
- 样本未做反调试/完整性自校验，或可绕过。

## 利用步骤

1. 识别文件头 `1B 4C 4A 02`，确认 Lua 5.1 字节码；若是嵌入在文本/资源中，先按偏移提取。
2. 用 unluac/luadec 等反编译，记录报错行；手工修补语法、补齐被优化掉的局部变量，使脚本可编译运行（可新建一个仅保留解密逻辑的副本）。
3. 定位字符串表 `var_0_19`、字母表 `var_0_22`、密钥表与解密循环；识别 `64^`、`% 65536`、`/ 256`、XOR 等特征。
4. 在解密结果写回表之前下断点（原文为 `var_0_26[iter_0_3] = var_0_28(var_0_32)` 前），运行并多次命中，从 watch/局部变量窗口读取 `var_0_26` 的明文。
5. 也可按循环逻辑用 Python/Lua 重写解码器，用已知明文（如 `Tamper Detected!`）验证字母表与密钥。
6. 汇总字符串，定位 C2、API 名、互斥体、注册表路径与窃密目标，再回到字节码/FFI 调用处还原行为。

## PoC

结构示意（字母表与密钥为占位，按样本 `var_0_22` 填充；仅演示 4×6-bit 累积与逐字节 XOR 的思路）：

```lua
-- 自定义字母表：64 个字符，索引从 0 开始
local alphabet = "<64-char-alphabet-from-sample>"
local map = {}
for i = 1, #alphabet do map[alphabet:sub(i, i)] = i - 1 end

local function decode(s, key)
  local out, acc, n = {}, 0, 0
  for i = 1, #s do
    local v = map[s:sub(i, i)]
    if v then
      acc = acc + v * 64 ^ (3 - n)
      n = n + 1
      if n == 4 then
        local b1 = math.floor(acc / 65536) % 256
        local b2 = math.floor(acc / 256) % 256
        local b3 = acc % 256
        local k = key[(#out % #key) + 1]
        out[#out + 1] = string.char(bit.bxor(b1, k))
        out[#out + 1] = string.char(bit.bxor(b2, k))
        out[#out + 1] = string.char(bit.bxor(b3, k))
        acc, n = 0, 0
      end
    end
  end
  return table.concat(out)
end
```

调试断点位置示意：

```lua
-- 原文循环末尾，解密结果写回字符串表处
var_0_26[iter_0_3] = var_0_28(var_0_32)
-- 在此行下断点，watch var_0_26，可看到 "Tamper Detected!" 等明文
```

## 变体与关联

- 变体：编码可换标准 Base64、URL-safe Base64、十六进制、RC4、XOR+压缩；字母表可随机化或按索引轮换，密钥可来自另一张表、注册表或 C2。
- 变体：解密可在字节码入口完成，也可在首次使用某字符串时惰性解密；后者断点应下在字符串取值函数内。
- 关联：CTF 中的 Lua 字节码异或/RC4 还原见 [[ctf-reverse-lua53-bytecode-xor-rc4]]；LuaJIT 字节码伪造闭包利用见 [[binary-pwn-sandbox-escape-lua51-bytecode-forloop-tvalue-fake-closure]]；本批样本的字节码载荷执行链见 [[pentest-c2-luajit-bytecode-text-payload-compiler-loader]]。
- 边界：字节码被进一步加密/压缩、解释器被修改导致反编译器无法识别、或调试器被反调试阻止时，需要先脱壳/修复或改用内存 dump。

## 检测与防御

- 检测（分析侧）：`.txt`/`.dat` 中出现 `1B 4C 4A 02`；反编译脚本含 `64^`、`% 65536`、`/ 256` 与自定义 64 字符表；运行时频繁调用 `string.sub`/`table` 构造大字符串表。
- 检测（防御侧）：监控加载 Lua 字节码的解释器进程；对伪装文本的字节码文件做文件类型识别而非只看扩展名。
- 分析建议：在隔离环境运行，禁用网络；用快照/断点 dump 而不要直接执行未知字节码；记录所有解密出的 C2/API 字符串作为 IOC。
