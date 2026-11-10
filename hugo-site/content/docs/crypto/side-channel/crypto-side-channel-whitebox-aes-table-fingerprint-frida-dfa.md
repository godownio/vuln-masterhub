---
id: crypto-side-channel-whitebox-aes-table-fingerprint-frida-dfa
title: 白盒 AES 查表实现指纹识别 + Frida 自动采样故障密文做 DFA 恢复主密钥
type: scenario
domain: crypto
path: crypto/side-channel
technique: whitebox-aes-table-fingerprint-frida-dfa-key-recovery
tags:
- crypto
- aes
- whitebox
- dfa
- fault-injection
- frida
- dynamic-instrumentation
- table-lookup
- ctf
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W4
  verified_at: '2026-11-08T20:46:08+08:00'
  notes: 已对照原文核对：Tbox 10*16*256 / TyiBox 9*16*256 / XorTable 16*16 表尺寸、末轮输入单字节故障、Frida NativeFunction+Interceptor 采样、输出 ^0x66 掩码剥除、phoenixAES+aes_keyschedule 流程均与正文一致；本次核对未读取图片，仅依据正文
url: /docs/crypto/side-channel/crypto-side-channel-whitebox-aes-table-fingerprint-frida-dfa/
draft: false
kb_aliases:
- 白盒 AES 查表实现
- Tbox TyiBox XorTable
- Frida 注入故障采样
- 白盒 AES 输出异或掩码
- phoenixAES 第 10 轮输入故障
- 表驱动 AES 密钥恢复
---

## 一句话结论

看到 10×16×256 的字节表（Tbox）+ 9×16×256 的 32 位表（TyiBox）+ 16×16 的异或表（XorTable）这种尺寸组合，基本可以判定是表驱动的白盒 AES；此后不必静态还原密钥，只要用 Frida 在轮函数入口自动篡改一个字节、批量采集 16~32 组故障密文，交给 phoenixAES 做差分故障分析拿到末轮轮密钥，再用 `aes_keyschedule` 逆扩展即可得到主密钥并解密。若输出端还叠加了固定字节异或（如 `^ 0x66`），必须先还原掩码再做 DFA。

## 原理

- **表尺寸即指纹**：`10*16*256` 对应 10 轮 × 16 个位置 × 256 个输入字节的 SubBytes+AddRoundKey 合成表（Tbox）；`9*16*256` 是前 9 轮把 Tbox 与列混淆再合并后的 32 位表（TyiBox，每项由 4 个分量移位拼接）；`16*16` 的小表只是 `i ^ j`，用于列混淆后的异或。若表按 4bit 拆分成 `16*16` 的二级索引，说明实现者还把每个字节拆成高低半字节查表（TyiTable 变体），这仍是同一套白盒结构。
- **结构仍等价标准 AES**：调换 ShiftRows/SubBytes 顺序、把 AddRoundKey 折进表之后，轮序仍是 9 个中间轮 + 1 个末轮（末轮无列混淆，只做字节替换再与 k10 异或）。因此差分故障分析的数学前提不变。
- **故障位置**：在末轮之前的输入（即第 10 轮输入 / 第 9 轮输出状态）注入单字节故障，经过末轮 SubBytes + ShiftRows 后扩散为密文中固定的 4 字节差异，可逐列解出末轮轮密钥 4 字节；16 个位置各采一组即够，多采几组可提高成功率。
- **为什么要自动采样**：手工在调试器里断点、改内存、抄密文，16 次以上极易出错且慢。用 Frida `Interceptor.attach` 挂在轮循环入口，在 `onEnter` 里按计数器判断当前是第几轮，命中目标轮时对状态指针指向的 16 字节随机改 1 个字节，函数返回后直接读输出缓冲区，循环调用 N 次即可一次性吐出全部故障密文。
- **输出掩码必须剥掉**：白盒实现常在最终输出上叠加固定字节异或（如 `result = v19 ^ 0x66`）作为廉价的外部编码。DFA 依赖的是 AES 真实输出，若掩码是逐字节常量异或，直接对每个密文字节再异或同值即可还原；若是查表式非线性编码，则要先反查该表。
- **末轮密钥到主密钥**：AES 密钥扩展可逆，用 `aes_keyschedule <末轮密钥> 10` 打印 K00..K10，K00 即主密钥；随后按 AES-ECB/NoPadding 解密目标密文。

## 触发条件

- 目标是表驱动的白盒 AES 实现（PE/ELF 均可），轮函数保留 10 轮结构，未做输入/输出线性编码之外的整体混淆。
- 能附加调试器或 Frida 到进程，且能在轮函数入口或末轮前拿到状态缓冲区地址（可从反汇编的轮循环参数、`shiftRows` 调用点识别）。
- 故障注入只改内存中的状态字节、不改程序逻辑；同一明文的正常密文可重复获取。
- 有 phoenixAES 与 Stark 的 `aes_keyschedule`（或等价的逆密钥扩展实现）。

## 利用步骤

1. 反汇编定位加密函数：找连续的 `shiftRows` 调用、4 个 32 位表指针（基址相差 `0x400` 的 `dword_xxx` 系列）、以及末尾的逐字节查表 + 异或。按基址差值算出各表跨度（`0x400 = 256 * 4` 字节），确认是 `10*16*256` 与 `9*16*256` 布局。
2. 若表被拆成半字节二级索引（存在大量 `& 0xF`、`>> 4` 取索引的嵌套查表），仍按标准 AES 处理，只是 DFA 前不要尝试手工还原表内容。
3. 打印一次正常密文：用 Frida `NativeFunction` 调用加密函数，传入固定明文与输出缓冲区，读出 16 字节。
4. 挂 `Interceptor.attach` 到轮循环入口，用计数器识别末轮（或直接用轮索引变量）；在 `onEnter` 中对 `this.context.<状态寄存器>` 加随机偏移写一个随机字节，`onLeave` 后读输出。
5. 循环调用 16~32 次，得到 1 组正常密文 + N 组故障密文；每行一个 16 字节十六进制写入 tracefile，首行放正常密文。
6. 若实现输出带固定异或掩码，先对 tracefile 每一字节异或该常量再喂给 phoenixAES。
7. 运行 `phoenixAES.crack_file('tracefile', verbose=0)` 得到末轮轮密钥。
8. 运行 `aes_keyschedule.exe <末轮密钥> 10`，取 K00 作为主密钥；用 AES-ECB/NoPadding 解密目标密文，必要时同时剥掉输出掩码。

## PoC

表尺寸指纹（反汇编里看到这种跨度组合即可判定）：

```text
0x400  * 10 * 16  -> 10*16*256 字节表（Tbox，SubBytes+AddRoundKey）
0x400  *  9 * 16  ->  9*16*256 32 位表（TyiBox，再并上 MixColumns）
0x100  * 16 * 16  -> 16*16 异或表（XorTable，i ^ j）
末轮末尾: 16 次 tbox[9][k][state[k]] 后再逐字节异或常量
```

Frida 自动采样（注入末轮前状态 + 读输出）：

```javascript
var base = Module.findBaseAddress(target);
var crypt = new NativeFunction(base.add(0x4BF0), 'pointer', ['pointer', 'pointer']);
var count = 0;
Interceptor.attach(base.add(0x4C2C), {
  onEnter: function () {
    count++;
    if (count === 9) {
      this.context.rdi.add(Math.floor(Math.random() * 16)).writeU8(Math.floor(Math.random() * 256));
    }
  }
});
for (var i = 0; i < 32; i++) {
  var pt = Memory.allocAnsiString('1234567890abcdef');
  var out = Memory.alloc(16);
  crypt(pt, out);
  console.log(Array.from(new Uint8Array(out.readByteArray(16)))
    .map(function (b) { return b.toString(16).padStart(2, '0'); }).join(''));
  count = 0;
}
```

剥掩码 + DFA + 逆密钥扩展：

```python
import phoenixAES

MASK = 0x66  # 输出端逐字节异或掩码，无掩码时置 0
rows = [l.strip() for l in open('raw_cipher.txt') if l.strip()]
fixed = [bytes(b ^ MASK for b in bytes.fromhex(r)).hex() for r in rows]
open('tracefile', 'w').write('\n'.join(fixed))
phoenixAES.crack_file('tracefile', verbose=0)
# Last round key -> 交给 aes_keyschedule
```

```text
> aes_keyschedule.exe <末轮密钥> 10
K00: <主密钥>      <- 用 K00 做 AES-128-ECB 解密
```

## 变体与关联

- 变体（半字节表）：把 Tbox 与 TyiTable 进一步拆成 `16*16` 二级索引（高低 4bit 分别查表再拼字节），指纹表现为大量 `& 0xF` 与 `>> 4/8/12/16/20/24/28` 的嵌套查表；DFA 流程不变，但静态读表基本不可行。
- 变体（故障注入点）：注入点可以放在末轮输入（第 9 轮输出）或第 8 轮 MixColumns 之后，phoenixAES 对前者解末轮密钥、对后者解第 9 轮密钥，二者都能逆扩展；关键是同一位置每次只改 1 个字节。
- 变体（采集方式）：用 IDA/x64dbg 条件断点手工改内存亦可，只是慢；用 Frida 的 `NativeFunction` + `Interceptor` 更适合需要几十组样本的场景。
- 关联：[[crypto-side-channel-whitebox-aes-dfa-round8-fault]]（同一 DFA 原语的调试器版本，故障注入在第 8 轮列混淆后）、[[ctf-reverse-whitebox-aes-runtime-table-reconstruction-mitm]]（白盒实现被完全混淆、无法注故障时改用运行时重建表 + 逐列 MITM）。
- 边界：若白盒实现了输入/输出的非线性双射编码（Chow 方案的外层编码），单字节故障在输出端不再呈现 4 字节可预测差异，DFA 需要先去编码；若程序带反调试且拒绝附加，Frida 采样会失败。

## 检测与防御

- 防御（实现侧）：白盒 AES 不应只靠查表隐藏密钥，输出端须叠加非线性双射编码并在关键路径做完整性校验；对状态缓冲区做运行时校验（每次轮函数前后比对校验和）可显著提高故障注入门槛。
- 防御（部署侧）：对可执行文件加壳/反调试只能延缓，不能阻止内存级故障注入；密钥保护应依赖硬件（TEE/白盒密码库）而非纯软件查表。
- 检测：进程被 Frida/调试器附加（`frida-server`、`ptrace`、异常线程）；加密函数返回的密文成批出现 4 字节差异；短时间内同一明文被反复加密数十次。
- 排查思路：拿不到主密钥时先确认是否漏了输出掩码、故障是否稳定落在同一轮、以及样本数是否够（每列至少 2 组更稳）。
