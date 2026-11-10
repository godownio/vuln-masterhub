---
id: code-analysis-reverse-windows-pe-simple-xor-packer-code-cave-stub
title: 最小 PE 异或壳：.code/.data 逐字节异或 0x7F + 节尾代码洞部署解密 stub + 改 AddressOfEntryPoint 与节 Characteristics 可写
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: pe-simple-xor-packer-code-cave-stub
tags:
- pe
- windows
- reverse
- packer
- xor
- entrypoint
- code-cave
- section-characteristics
- asm
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V361
  verified_at: '2026-11-09T02:28:41+08:00'
  notes: 已对照原文全文与9张图核对：01/02.png 为 .code(0x200)/.data(0x400) 异或后密文，03.png 为 FOA 0x3D9 写入 0x27 字节 stub（B8..B9 D9 01..FF E0），04.png 为 EP=0x11D9，05.png 为 .code Characteristics 改 0xE0000060，06.png 为加壳后正常弹出 Hello, Snake! MessageBox。四步流程、0x1D9 解密长度、RVA 换算、实例值均与原文一致。原文为技术教学无组件版本，affected_versions 留空正确。dedup top 候选（恶意样本 XOR loader、EP shellcode 补丁、.data 节 XOR 内嵌 PE）均为不同场景/构造，与同篇'加密导入表'卡为递进但原子不同的两项技术，dedup_review 成立。dup-scan.json（2026-11-08 19:10）早于建卡（2026-11-09 01:43），无涉及本卡 pair。未验证点：未在本机重跑 Python/汇编与 PE；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-pe-simple-xor-packer-code-cave-stub/
draft: false
kb_aliases:
- 简单 PE 壳
- PE 加壳
- 异或壳
- section XOR packer
- 解密 stub
- 入口点重定向
- Section Characteristics 可写
---

## 一句话结论

给 PE32 程序加一个最小壳只需四步：把 `.code`/`.data` 节按字节异或加密、在可执行节尾部的空余空间写入一段"解密两节并跳回原入口"的汇编 stub、把 `AddressOfEntryPoint` 改成 stub 的 RVA、再把该节 `Characteristics` 加上可写位——程序启动后先由 stub 原地解密，再跳回原始入口正常执行，静态扫描因此看不到明文代码与字符串。

## 原理

- **加壳目的**：壳改变被保护程序，使静态字符串搜索/代码分析失效；本例只做异或加密，重点是 PE 结构（节、FOA/RVA、入口点、节属性）的实际运用。
- **加密对象**：对 `.code`（FOA 0x200、大小 0x200）与 `.data`（FOA 0x400、大小 0x200）逐字节异或 `0x7F`；因为异或自反，解密与加密是同一段逻辑。
- **stub 位置与内容**：stub 用汇编编写——`mov eax, 0x401000`（`.code` 加载后地址 = ImageBase 0x400000 + RVA 0x1000）、`mov ecx, size`、`xor byte ptr [eax], 0x7F`/`inc eax`/`loop`，对 `.data`（0x402000）同样一段，最后 `mov eax, OEP(0x401000)`、`jmp eax`。汇编后约 0x27 字节，放进 `.code` 节尾部（FOA 0x400 − 0x27 = 0x3D9）。
- **为什么要缩小解密长度**：stub 自己就位于 `.code` 尾部，若仍对整个 0x200 字节解密，会把正在执行的 stub 一并异或掉，等于运行时改写自身代码，必然崩溃；因此 `.code` 只解密前 0x1D9 字节（0x200 − 0x27）。
- **入口点换算**：`AddressOfEntryPoint` 是 RVA，stub 的 FOA 0x3D9 按 `RVA = FOA − 节 FOA + 节 RVA` 换算为 `0x3D9 − 0x200 + 0x1000 = 0x11D9`，写入 PE Optional Header（本例 FOA 0xA8）。
- **必须改节属性**：原 `.code` 的 `Characteristics = 0x60000020`（CNT_CODE | MEM_EXECUTE | MEM_READ）；stub 要写自己所在节的内存，缺失 `IMAGE_SCN_MEM_WRITE` 会触发访问违例。改成 `0xE0000060`（增加 MEM_WRITE 与 CNT_INITIALIZED_DATA）后即可正常运行。
- **边界**：要求镜像基址固定为 0x400000（或按实际基址换算 stub 中的绝对地址）、节内有足够代码洞容纳 stub；只加密节内容不改导入表，因此 IAT 与导入解析不受影响。

## 触发条件

- 目标为 32 位 PE，节内容可被替换且镜像基址/节布局已知（本例为手工构造的最小 PE）。
- 可执行节尾部有足够空余（≥ stub 长度，本例 0x27 字节）作为代码洞。
- 程序无完整性校验/签名验证；否则改动入口点与节内容会暴露或导致校验失败。
- stub 中的绝对地址与目标加载基址一致（ASLR/重定位场景需改写）。

## 利用步骤

1. 用 Python 读取文件，把 `.code`（0x200–0x3FF）与 `.data`（0x400–0x5FF）逐字节异或 0x7F 并保存为 `packed_PE.exe`。
2. 用汇编器生成 stub（解密两节 + 跳 OEP），确认其长度；把 `.code` 的解密循环计数改为 `0x200 − stub_len`。
3. 把 stub 字节流写到 `.code` 尾部 FOA `0x400 − stub_len`（本例 0x3D9）。
4. 计算 stub 的 RVA（`FOA − 0x200 + 0x1000`，本例 0x11D9），写入 `AddressOfEntryPoint`。
5. 把 `.code` 的 `Characteristics` 由 0x60000020 改为 0xE0000060（加 MEM_WRITE）。
6. 运行 `packed_PE.exe`：stub 解密 `.code`/`.data` 后跳回 0x401000，程序功能不变；静态查看节数据只见密文。

## PoC

```python
key = 0x7F
with open("PE.exe", "rb") as f:
    pe = bytearray(f.read())
for i in range(0x200, 0x400):   # .code
    pe[i] ^= key
for i in range(0x400, 0x600):   # .data
    pe[i] ^= key
with open("packed_PE.exe", "wb") as f:
    f.write(pe)
```

```asm
; stub：先解密，再跳回原入口（ImageBase = 0x400000）
mov eax, 0x401000
mov ecx, 0x1D9          ; 0x200 - stub 长度 0x27，避免解密自身
start1:
xor byte ptr [eax], 0x7F
inc eax
loop start1
mov eax, 0x402000       ; .data
mov ecx, 0x200
start2:
xor byte ptr [eax], 0x7F
inc eax
loop start2
mov eax, 0x401000       ; 原入口点 OEP
jmp eax
```

```text
; 关键头部字段（本例）
FOA 0xA8  AddressOfEntryPoint = 0x11D9
FOA 0x188 .code Characteristics = 0xE0000060
; 上述汇编对应的字节流（0x27 字节）写入 FOA 0x3D9
B8 00 10 40 00 B9 D9 01 00 00 80 30 7F 40 E2 FA
B8 00 20 40 00 B9 00 02 00 00 80 30 7F 40 E2 FA
B8 00 10 40 00 FF E0
```

原文以该流程给手工构造的 PE 加壳，运行后正常弹出原始程序的 MessageBox 对话框。

## 变体与关联

- **算法变体**：异或换 RC4/AES/滚动密钥；按节加密时可用更小的按页解密 stub；stub 内加反调试、校验和自检。
- **布局变体**：不占用节尾代码洞，而是新增一个可写可执行节存放 stub（见导入表加密版本 [[code-analysis-reverse-windows-pe-import-table-encrypt-unpack-section-iat-rebuild]]）。
- **相关 PE 修改**：仅改入口点注入 shellcode 见 [[code-analysis-reverse-windows-pe-section-squeeze-entrypoint-shellcode-patch]]；在既有节尾造函数桩见 [[code-analysis-reverse-windows-pe-exe-add-import-thunk-rdata-string-rip-relative]]。
- **对抗/脱壳**：此类壳 OEP 在解密循环结束后 `jmp` 处，脱壳时可在 stub 尾部下断、dump 内存并修复 IAT；节同时可写可执行、入口点不在原代码节是典型特征。

## 检测与防御

- **静态特征**：节数据熵升高、字符串不可读；`AddressOfEntryPoint` 指向节尾代码洞或非常规节；节 `Characteristics` 同时含 MEM_WRITE 与 MEM_EXECUTE；节原始数据尾部出现解密循环/`jmp` 小段代码。
- **动态特征**：入口处先对自身映像大量逐字节写（解密循环），随后跳转到他处；进程内存中出现先密后明的节；EP 不在原 `.text`/`.code` 起点。
- **防御**：发布前对可执行文件做签名与完整性校验；AV/EDR 对 W+X 节与 EP 异常告警；逆向侧按"解密循环结束点即 OEP"定位并 dump，修复 IAT 后可还原原始代码。
