---
id: code-analysis-dynamic-debugging-ini-config-xor-add-decrypt-api-breakpoint
title: 客户端软件加密配置还原：CreateFileA/ReadFile API 断点锁定密文缓冲区，内存访问断点定位逐字节 xor/add 解密循环（xor 0xBD + add 0x69）提取服务器地址
type: scenario
domain: code-analysis
path: code-analysis/dynamic/debugging
technique: config-decrypt-api-breakpoint-locate
aliases:
- 配置文件解密动态调试
- ini 配置 xor 加密还原
- GreenVPN 配置解密
- API 断点定位解密算法
tags:
- reverse
- debugging
- ollydbg
- config-decrypt
- windows
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-23
  verified_at: '2026-11-08T13:27:07+08:00'
  notes: 已对照原文核对：断点定位链（CreateFileA 参数 GreenVPN\system.ini → 句柄 0x20C → edi=0x185690 → ReadFile Buffer=0x1857C8 → 内存访问断点 → 00407704 处 xor 0xBD/add 0x69 循环）与 22 张截图逐一一致；密文/明文对比及 de_ 前缀文件还原结果均有截图佐证。dedup 候选为 shellcode/PE 解密等不同场景，非同一链。
---

# 客户端软件加密配置还原：CreateFileA/ReadFile API 断点锁定密文缓冲区，内存访问断点定位逐字节 xor/add 解密循环（xor 0xBD + add 0x69）提取服务器地址

## 一句话结论

客户端软件（如加速器/代理类）为隐藏代理服务器、更新源地址常把 system.ini/module.ini 等配置文件做整体加密；可在 OllyDbg/x32dbg 中对导入表的 `CreateFileA`、`ReadFile` 下断确认密文来源与读取缓冲区，再对缓冲区设内存访问断点，单步筛出「逐字节 xor 常量 + add 常量」解密循环（本例 `xor dl,0xBD; add dl,0x69`），还原为等价 C 代码后离线解密全部配置文件，直接得到形如 `host01=www.xxx.com`、`(PPTP+L2TP+OpenVPN)=us1.xxx.cc|10339` 的服务器清单。

## 原理

- 低强度整体加密的配置文件仍必须被程序自身解密后使用，解密例程一定在读文件之后、使用明文之前执行，因此「文件 API 断点 → 数据流断点」的链路必然能命中解密代码。
- 定位链路：导入表搜索 `KERNEL32.CreateFileA` 下断（调用处参数可见 `FileName=C:\...\GreenVPN\system.ini`、GENERIC_READ、OPEN_EXISTING），返回句柄（0x20C）后跟踪句柄在内存中的存放地址（edi=0x00185690），步入以该句柄为参的封装函数，其中可见 `ReadFile(hFile=0x20C, Buffer=0x001857C8, BytesToRead=19000)`；随后对该 Buffer 地址设「断点→内存访问」，程序再次运行即停在消费密文的代码。
- 解密循环识别：在两次断点间单步，观察到原密文区域一半已变明文即为解密循环所在（`sub eax,edx` 得密文长度，循环体 `mov dl,[ecx]; xor dl,0xBD; add dl,0x69; mov [ecx],dl; inc ecx; dec eax; jnz`）。逐字节 xor+add 的混合作业比纯 xor 多一层迷惑，但对全文件统一密钥/常量，无分组无轮次，还原成本极低。
- 与内存执行解密（运行时自解密 shellcode）不同，此类配置解密例程读取的是磁盘文件、输出到固定缓冲区，故文件 API 断点是比 VirtualProtect 断点更直接的入口。

## 触发条件

- 拿到目标客户端样本及其加密配置文件（ini/elf 式文本配置，体积小）；
- 样本为 32 位 PE、未加壳或可脱壳（导入表可见 CreateFileA/ReadFile）；
- 配置解密发生在启动路径上（运行即可触发）。

## 利用步骤

1. 运行目标软件确认其加载加密配置（system.ini/module.ini/module_en.ini 内容为非明文）。
2. OllyDbg 打开主程序，在可执行模块导入表中搜 `CreateFile`，对 `KERNEL32.CreateFileA` 所有调用点下断。
3. 断下后从栈上看 lpFileName 确认目标文件；记下返回句柄，继续运行/单步，找到句柄被写入的内存地址与后续引用。
4. 步入引用句柄的函数，确认其内部调用 `ReadFile`，记下 Buffer 地址（如 0x001857C8）与读取长度。
5. 在数据窗口对 Buffer 设「断点→内存访问」，重新运行，程序停在处理密文的代码区间；在两个断点间单步并对照内存窗口，密文逐渐变明文的那段循环即解密算法。
6. 按汇编还原等价 C：对文件每字节依次 `c ^= 0xBD; c += 0x69;`（字节序），批量处理所有加密配置并输出 de_ 前缀文件。
7. 明文配置直接给出更新源、Web 站点、免费/VIP 节点（协议|地址|端口）等服务器信息。

## PoC

```c
// 还原后的解密核心（对整文件逐字节）
size_t size = fread(buffer, 1, sizeof(buffer), file);
for (size_t i = 0; i < size; i++) {
    buffer[i] ^= 0xBD;
    buffer[i] += 0x69;
}
fwrite(buffer, 1, size, out);   // de_system.ini 等
```

原文验证：还原代码输出的密文/明文与调试器内存完全一致，成功解出 system.ini（更新源 host01/host02、WEB 站点）与 module.ini/module_en.ini（免费北-01-(PPTP+L2TP+OpenVPN)=us1.freegjsq.cc|10339|tcp|udp 等节点清单）。

## 变体与关联

- 变体：常量组合换成 xor+sub、双轮 xor、按索引变化的密钥（`key[i%len]`）时，同一断点链路仍适用，只是循环体多读一个密钥流。
- 变体：配置加密在 ini 解析前/后进行（GetPrivateProfileIntA 出现在调用栈附近时可判断明文化时点）。
- 关联：[[code-analysis-dynamic-debugging-multi-layer-shellcode-decrypt-dump]]（多层编码解密还原与断点转储，本卡是其单层低强度变体）。
- 关联：[[code-analysis-dynamic-debugging-virtualprotect-runtime-decrypt-ida]]（运行时自解密场景用 VirtualProtect 断点的姊妹方法）。

## 检测与防御

- 防御（软件开发视角）：配置文件加密应使用带密钥派生的对称算法并把密钥与机器绑定，避免全文件统一常量的逐字节变换；敏感服务器地址可拆分存放/按需拉取。
- 检测（取证视角）：对可疑客户端，优先检查随附 ini/配置文件熵值；熵高但程序不依赖外部密钥库时，可按本链路动态调试提取真实 C2/节点列表用于封堵与溯源。
