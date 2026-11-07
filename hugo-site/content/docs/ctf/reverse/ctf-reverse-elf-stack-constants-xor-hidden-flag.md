---
id: ctf-reverse-elf-stack-constants-xor-hidden-flag
title: 静态 ELF 栈上成对常量异或还原隐藏 flag
type: scenario
domain: ctf
path: ctf/reverse
technique: elf-stack-constant-pair-xor
tags:
- ctf
- reverse
- elf
- xor
- static-analysis
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V124
  verified_at: '2026-11-06T04:31:58+08:00'
  notes: '已对照原文核对：64 位静态未 strip ELF、主流程固定打印 invalid、栈上成对 8 字节常量（[rsp-0x48]^[rsp-0x08]=Enter Se、[rsp-0x40]^[rsp+0x00]=cret: 验证配对）、6 对常量异或还原 VishwaCTF{50rry_17_w4s_r3411y_m3s53d_UP!!!} 均一致。未验证点：无 ELF 附件，PoC 未本机复跑；原文无版本信息；frontmatter 无 sources/source_url。'
url: /docs/ctf/reverse/ctf-reverse-elf-stack-constants-xor-hidden-flag/
draft: false
kb_aliases:
- Messed Up
- 栈常量异或
- 隐藏 flag 静态提取
- ELF 常量对
---

## 一句话结论

程序无论输入什么都打印 invalid 时，flag 可能并不参与校验，而是被拆成多组 8 字节常量压栈；把对应位置的常量两两异或、按小端转字节并去掉 NUL，即可静态还原隐藏的 flag（同样的方法也能还原提示字符串）。

## 原理

- 编译器/作者可以把字符串拆成两半，分别以立即数写入栈上的相邻槽位；运行时再异或还原，但校验流程可能根本不使用它。
- 文章在 `[rsp-0x48]`、`[rsp-0x38]` 等位置找到成对常量，例如 `[rsp-0x48] ^ [rsp-0x08] = "Enter Se"`，验证了异或还原方式。
- flag 部分由 6 对常量组成，每对异或得到 8 字节小端字符串片段；拼接后得到完整 flag。
- 因为程序主流程固定打印 invalid，不能靠输入触发成功分支；必须静态提取常量并还原。

## 触发条件

- 静态链接/未 strip 的 ELF，初始化阶段有大量 8 字节立即数写入栈。
- 常量成对出现，异或后得到可打印 ASCII。
- 程序没有真正的成功分支，或 flag 不参与输入校验。

## 利用步骤

1. 反汇编 `main`/初始化代码，记录写入栈的 8 字节常量及其槽位。
2. 按“相隔固定距离”配对（如 `[rsp-0x48]` 与 `[rsp-0x08]`）。
3. 对每对做 64 位异或，按小端转 8 字节，去掉尾部 `\x00`。
4. 拼接所有片段；先用提示字符串（如 `Enter Secret:`）验证配对方式。
5. 输出 flag。

## PoC

```python
parts = [
    0x5b70de7570bc89c2 ^ 0x0f33bf0218cfe094,
    0x794b3d6bbf3f238f ^ 0x26324f198f0a58c9,
    0x212aa49b64d7e65d ^ 0x5375d7af1388d16c,
    0x90bafc29c34b62bd ^ 0xa3d7a350f27a568e,
    0xa0564f32e8a3db99 ^ 0x81061a6d8c90eeea,
    0x0000000000b4c144 ^ 0x0000000000c9e065,
]
flag = b"".join(x.to_bytes(8, "little").rstrip(b"\x00") for x in parts)
print(flag.decode())
```

## 变体与关联

- 还原运算可换成加/减/循环移位/查表；先找提示字符串验证。
- 常量可能在 `.rodata` 而非栈上，或在构造函数中初始化。
- 关联：[[ctf-reverse-printable-ascii-caesar-hidden-permutation-table]]（常量变换）、[[ctf-reverse-byte-pair-add-rol8-buffer-rotate-inverse]]（可逆变换）。

## 检测与防御

- 这是 CTF 逆向题型；防御上可把 flag 加密存储、运行时才解密，或加入反静态分析。
- 检测：ELF 初始化代码中出现大量成对 8 字节立即数写入栈。
