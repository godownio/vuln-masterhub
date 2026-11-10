---
id: code-analysis-reverse-windows-shellcode-rolling-xor-embedded-cs-pe
title: ShellCode 滚动 XOR 自解密内嵌 Cobalt Strike PE：0x59 初值 + xor 后 add 明文的倒序循环还原 MZ
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: shellcode-rolling-xor-embedded-pe-0x59
tags:
- windows
- reverse
- shellcode
- xor
- rolling-key
- embedded-pe
- cobalt-strike
- malware-analysis
- x64dbg
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V287
  verified_at: '2026-11-08T05:44:18+08:00'
  notes: 已对照原文与17图（含zoom14/15/16）核对：mov r13b,0x59; mov rcx,0x43A06; xor [r14+rcx],r13b; add r13b,[r14+rcx]; loop 倒序循环（14/zoom14/16），循环后r14处4D 5A MZ恢复、lea rbx,[r14+4];add rbx,0x16E3C;call rbx（15/zoom16），CS配置windows-beacon_https-reverse_https/443/sleep5987/jitter50/多IP+/jquery-3.3.1.min.js/spawnto svchost/GET/POST（16/zoom15）均一致；PoC倒序+offset0保留M+密钥随明文累加与指令一致。dedup除自身外均related（mz-no、split-xor等）；dup-scan与14740/14736 related。未验证点：未用样本密文跑脚本；无组件版本；frontmatter无sources/source_url。
url: /docs/code-analysis/reverse/windows/code-analysis-reverse-windows-shellcode-rolling-xor-embedded-cs-pe/
draft: false
kb_aliases:
- 滚动 XOR 自解密
- 0x59 XOR
- xor 后 add 明文
- shellcode 内嵌 PE
- MZ 还原
- Cobalt Strike beacon 提取
- 倒序 XOR 循环
---

## 一句话结论

外层 shellcode 先用 `mov r13b,0x59` 设定滚动密钥，再从 `r14+0x43A06` 向 `r14+1` 倒序执行 `xor byte [r14+rcx],r13b; add r13b,byte [r14+rcx]; loop`——密钥随刚解出的明文字节不断累加——解密完成后该区域呈现完整的 `MZ` 头与 DOS stub，随后 shellcode 以 `add rbx,0x16E3C; call rbx` 跳入内嵌 PE 入口；该 PE 是 Cobalt Strike beacon，可解析出 HTTPS reverse、伪装 `/jquery-3.3.1.min.js` 的多个 C2 与 svchost spawnto 等配置。

## 原理

- **滚动 XOR 的密钥更新**：循环体两条指令顺序很关键。`xor byte ptr ds:[r14+rcx], r13b` 先把目标字节与当前密钥异或，结果直接写回内存；紧接着 `add r13b, byte ptr ds:[r14+rcx]` 读取的是**已解密的明文字节**并累加到密钥。因此第 i 个字节的密钥等于 `0x59 + 前面所有明文字节之和 (mod 256)`，每个字节的密钥都不同，密文中不出现固定周期，静态频率/重复模式检测更难。
- **倒序与偏移 0 的特殊性**：`mov rcx,0x43A06` 后 `loop` 每次先写 `[r14+rcx]` 再把 `rcx` 减一，因此循环覆盖偏移 `0x43A06` 到 `1`，偏移 `0` 不在循环内。样本在 `r14` 处保留的首字节是 `0x4D`（'M'），加密态下看不到完整的 `MZ` 双字节特征；解密后整个区域才是 `4D 5A 90 00 ...`。复现时若把偏移 0 也异或，会破坏 PE 头第一字节。
- **解密后的跳转**：循环结束后的代码 `lea rbx,[r14+4]; mov rdi,rbx; add rbx,0x16E3C; call rbx` 直接调用内嵌 PE 的入口（`ImageBase + 0x16E3C`），而不是另起进程；此前 `push r10/push rbp` 等指令构造了新栈帧，符合 shellcode 自带 PE loader 的执行形态。
- **为什么采用这种写法**：滚动 key 让每个字节的密钥依赖明文历史，简单的单字节 XOR 扫描/已知明文攻击失效；内嵌完整 PE 便于把 Cobalt Strike beacon（反射 DLL/shellcode）打包进外层 loader；`M` 保留在明文使 `MZ` 特征在加密态缺失，进一步降低内存扫描命中率。
- **家族确认与配置**：从内存 dump 或离线解密出的 PE 可用 CobaltStrikeParser/1768.py 解析配置，样本字段包括 `payload type = windows-beacon_https-reverse_https`、`port = 443`、`sleep = 5987`、`jitter = 50`、`server,get-uri` 为多个 IP 加 `/jquery-3.3.1.min.js`、`spawnto_x86 = %windir%\syswow64\svchost.exe`、`spawnto_x64 = %windir%\sysnative\svchost.exe`、`get-verb = GET`、`post-verb = POST` 等，可确认 Cobalt Strike 并输出 IOC。
- **与同类技术的差异**：已有“PE 签名改 NO + 滚动 XOR（dl 初值 3）”的样本；本样本 PE 头未伪装（标准 MZ + DOS stub），初值 0x59、长度 0x43A06，且循环倒序、偏移 0 不加密。两者同属“shellcode 滚动 XOR 解出内嵌 PE”，但参数与 PE 头处理不同，分析脚本需按样本调整。

## 触发条件

- 已取得外层 shellcode（从 Java `enqueue` 执行前、进程内存 dump，或文件解密后的 buffer）。
- shellcode 在 x64 Windows 进程中执行；分析者可使用 x64dbg/IDA 观察循环。
- 已知或可从反汇编读出：密钥初值、循环计数、密文起始指针、PE 入口偏移。
- 若要离线还原，需要完整的加密区字节（偏移 1..0x43A06）与首字节 `0x4D`。

## 利用步骤

1. 在 IDA/x64dbg 中定位循环特征：`mov r13b, imm8`、`mov rcx, <len>`、`lea r14, [<addr>]`、`xor byte [r14+rcx], r13b`、`add r13b, [r14+rcx]`、`loop`。
2. 记录初值（样本为 `0x59`）、计数（`0x43A06`）、起始地址（`r14`）以及偏移 0 是否参与循环。
3. 在 `loop` 结束后下断点，直接 dump `r14` 起的 `0x43A07` 字节（或按算法离线还原）。
4. 校验 dump：前两字节为 `4D 5A`，`e_lfanew` 处为 `PE\0\0`，DOS stub 含 `This program cannot be run in DOS mode`；确认入口偏移与 `call rbx` 的目标一致。
5. 对还原后的 PE 跑 Cobalt Strike YARA 规则与 1768.py/CobaltStrikeParser，提取 C2、端口、sleep/jitter、URI、User-Agent、spawnto 等配置。
6. 回溯上层 Java 加载链，把 Java 文件对 XOR、`enqueue` 执行与本次 shellcode 自解密串成完整链。

## PoC

离线还原脚本（按样本参数；倒序、偏移 0 保留）：

```python
# enc: 从 r14 起读取的 0x43A07 字节；enc[0] 是明文 'M'
enc = bytearray(open("stage_enc.bin", "rb").read())
assert enc[0] == 0x4D
key = 0x59
for off in range(0x43A06, 0, -1):
    p = enc[off] ^ key
    enc[off] = p
    key = (key + p) & 0xFF
open("stage.dec.bin", "wb").write(enc)
assert enc[:2] == b"MZ"
```

x64dbg 操作：在 `loop` 指令后的地址下断点，执行到断点后 `dump r14`，长度 `0x43A07`；或用脚本对 `r14` 指向的内存直接按上述算法还原。

```text
yara cobaltstrike_rules.yar stage.dec.bin
python 1768.py stage.dec.bin
```

## 变体与关联

- **密钥更新变体**：`xor` 后用密文字节更新 key、用固定 key、用 `add`/`sub` 交替、用滚动索引表；循环方向也可能正序。必须以反汇编为准，不能套用固定算法。
- **PE 头伪装变体**：标准 MZ；只保留首字节 `M`；PE 签名改 `NO`；DOS stub 改写；节名去点。参见 [[code-analysis-reverse-windows-mz-no-embedded-pe-xor-shellcode]]（同类滚动 XOR + 内嵌 PE，PE 签名改 NO、初值 3）。
- **载荷家族变体**：Cobalt Strike beacon、Metasploit stage、Donut 生成的 loader、自写反射 DLL。
- **关联**：[[pentest-c2-java-tools-jar-windowsvirtualmachine-enqueue-shellcode]]（上层 Java 通过 `enqueue` 执行本 shellcode）、[[pentest-c2-java-jre-lib-ejs-keyfile-xor-staged-loader]]（Java 侧先用文件对 XOR 解出外层 shellcode）、[[pentest-initial-access-lnk-ftp-dat-caret-javaw-jar-loader]]（投递链）。
- **配置/检测**：[[defense-detection-cobaltstrike-checksum8-ja3-beacon-config-extract]]（CS 配置与流量提取）、[[defense-detection-cobaltstrike-domain-fronting-config]]（同类 `/jquery-3.3.1.min.js` 伪装 URI 与 spawnto 配置）。
- **边界**：若样本在循环前已把首字节也加密，需把偏移 0 纳入；若 `r14` 指向的内存被重定位/加密页保护，dump 时机要选在循环结束后。

## 检测与防御

- **静态检测**：shellcode 中出现 `mov r13b, imm8; lea r14; xor [r14+rcx], r13b; add r13b,[r14+rcx]; loop` 的滚动 XOR 模式；高熵数据块后紧跟 `MZ`/PE 结构；`call` 到非模块地址。
- **动态检测**：javaw/java 等进程出现私有提交/RWX 内存、内存中出现 `MZ` 头与 DOS stub、随后从该内存执行；网络侧出现多个 IP 的 `/jquery-3.3.1.min.js` 请求与固定 sleep/jitter 心跳。
- **内存取证**：在 `loop` 后或 `call rbx` 前 dump `r14` 区域；对 dump 做 YARA（Cobalt Strike）与配置解析，提取 C2、URI、UA、spawnto。
- **防御**：EDR 监控非模块内存执行与私有内存中的 PE 结构；封禁样本 IOC（C2 IP/URI 模式）；对 Java 进程的网络外连做基线；限制用户目录/JRE 目录的载荷落地。
- **响应**：保存解密后的 PE 与配置，关联同批次 LNK、jar、JRE lib 伪装文件；排查相同 URI 模式的其它主机。
