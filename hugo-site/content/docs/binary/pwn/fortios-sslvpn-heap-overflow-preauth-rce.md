---
id: fortios-sslvpn-heap-overflow-preauth-rce
title: FortiOS SSL-VPN 堆溢出未认证 RCE（特大 Content-Length 触发）
type: scenario
domain: binary
path: binary/pwn
technique: SSL-VPN 堆溢出 ROP/Shellcode 利用
tags:
- fortigate
- fortios
- sslvpn
- heap-overflow
- preauth-rce
affected_versions: FortiOS SSL-VPN 7.2.0-7.2.2, 7.0.0-7.0.8, 6.4.0-6.4.10, 6.2.0-6.2.11, 6.0.15 及更早；FortiProxy SSL-VPN 7.2.0-7.2.1, 7.0.7 及更早
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-20
  verified_at: '2026-11-08T12:49:08+08:00'
  notes: 已对照原文核对：affected_versions 与原文引用的官方公告原文逐字一致(FortiOS 7.2.0-7.2.2/7.0.0-7.0.8/6.4.0-6.4.10/6.2.0-6.2.11/6.0.15及更早、FortiProxy 7.2.0-7.2.1/7.0.7及更早)；frontmatter cve 空串已移除；正文无 CVE 编号描述，alias 标 CVE-2022-42475 同型属推断但原文公告文本与该 CVE 公告一致；dedup 候选为不同产品/通用技术卡，无重复；未验证点：gadget 地址与偏移未实际复现
url: /docs/binary/pwn/fortios-sslvpn-heap-overflow-preauth-rce/
draft: false
kb_aliases:
- FortiGate SSL-VPN 堆溢出
- CVE-2022-42475 同型漏洞
---

# FortiOS SSL-VPN 堆溢出未认证 RCE（特大 Content-Length 触发）

## 一句话结论

FortiOS/FortiProxy SSL-VPN 存在堆缓冲区溢出（CWE-122），远程未认证攻击者向 `/remote/login` 发送带超大 `Content-Length`（如 115964116992）与超长 POST payload 的特制 HTTPS 请求即可在 sslvpnd 中劫持控制流，结合 ROP 调用 `system`/`execl` 或 `mprotect`+shellcode 执行任意命令，拿到设备 shell。

## 原理

SSL-VPN 的 `/remote/login` 处理器在读取请求体时按攻击者控制的 Content-Length 分配/写入，特定长度区间下触发堆溢出，覆盖 sslvpnd 的返回地址/关键结构。目标进程未开 PIE 时代码段基址固定（可从调试环境直接抄 gadget 地址），溢出偏移 0x560 后接 ROP 链、0x620 处放跳板（`push rdx; pop rsp; ret` 型）把栈切到攻击者数据区。无 `/bin/sh` 的加固环境则先用 ROP 调 `mprotect` 把残存栈段改 RWX，再 `jmp rsp` 执行尾部 shellcode 完成 `execl("/bin/tftp",...)` 下载文件等操作——溢出到 ROP 的完整预认证利用链。

## 触发条件

- 目标 FortiOS/FortiProxy 版本在受影响区间且 SSL-VPN（443/4433 端口）对外可达；
- POST `/remote/login` + 超大 Content-Length + payload 达到特定长度（本例 0x620 布局）；
- 无需任何认证。

## 利用步骤

1. 构造 payload：`'a'*0x560 + ROP`，`ljust(0x620)` 后接跳板地址（0xfebbaa：`push rdx; pop rsp; ret`）与命令参数区（`/bin/busybox telnetd -l /bin/sh -b 0.0.0.0 -p 22`）。
2. HTTPS POST `/remote/login`，Header 填 `Content-Length: 115964116992`。
3. 带调试环境先验证 ROP 调 `system` 执行 telnetd；加固环境改用 mprotect(0x7ff1e0f42000 附近 rw-p 段, 0x200000, 7) + `jmp rsp` 执行 shellcode。
4. 命令执行成功后 telnet 22 端口拿到 root shell（FortiOS 无独立 sh 环境时配合 node/busybox 恢复场景）。

## PoC

无 PoC（原文含完整 Python 利用脚本：ssl.wrap_socket 后发送 `POST /remote/login` + `Content-Length: 115964116992` + ROP payload，调试环境成功 telnetd 上线；gadget 列表含 `push rdx,pop rdi.ret`(0x257008a)、`pop rsi; ret`(0x530c8e)、`call mprotect`(0x43F3D0)、`jmp rsp`(0x5dc96d)、`execl`(0x43A160) 等）。

## 变体与关联

- 变体：不同版本 gadget 地址不同需重新收集；同型堆溢出触发长度可能随版本变化，需 fuzz Content-Length。
- 关联：mprotect+jmp rsp 转 shellcode（见配套通用卡）；利用 node 恢复受限 shell 环境；固件 patch 调试环境是开发本利用的前提。
- 缓解：升级修复版本、限制 SSL-VPN 暴露面、WAF/IPS 拦截异常 Content-Length。

## 检测与防御

- 检测：SSL-VPN 访问日志中出现超大 Content-Length（>10^9）、/remote/login 异常长度 POST、进程崩溃重启记录。
- 防御：及时升级（官方 critical 公告）、对 SSL-VPN 门户加 MFA/IP 白名单、部署 IPS 特征。
