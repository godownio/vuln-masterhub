---
id: defense-forensics-openssh-session-key-memory-sshenc-pcap-decrypt
title: 从 ssh/sshd 进程内存提取 sshenc 会话密钥并解密 SSH pcap 会话
type: scenario
domain: defense
path: defense/forensics
technique: openssh-sshenc-memory-key-pcap-decrypt
tags:
- forensics
- ssh
- openssh
- session-key
- sshenc
- memory-dump
- gdb
- pcap
- chacha20-poly1305
- traffic-decrypt
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V208
  verified_at: '2026-11-07T02:27:52+08:00'
  notes: 已对照原文与43张图核对：sshenc 结构体字段、GDB info proc mappings/dump memory 0x02445000-0x02501000、Go 指针扫描逻辑、64字节 chacha20-poly1305 key 的 key.json、network-parser 命令及解密输出（kali/kali、uname -ar 与 ifconfig）均与原文一致；本卡为防御/取证卡（非漏洞卡），未设 affected_versions 合理。未验证点：PoC 未本机复跑；frontmatter 无 sources/source_url（全库惯例）。
url: /docs/defense/forensics/defense-forensics-openssh-session-key-memory-sshenc-pcap-decrypt/
draft: false
kb_aliases:
- SSH 会话密钥提取
- sshenc 结构体扫描
- OpenSSH-Session-Key-Recovery
- OpenSSH-Network-Parser
- SSH 流量解密
- chacha20-poly1305 SSH 解密
---

## 一句话结论

在可读取 ssh/sshd-session 进程内存的主机上（root/GDB/ptrace），用 `info proc mappings` 找到 heap 并 `dump memory` 导出，再按 `struct sshenc` 的字段约束扫描内存，即可提取 SSH 会话密钥（name/cipher/enabled/key_len/iv_len/block_size/key/iv）；把 key.json 交给 OpenSSH-Network-Parser 或自研解析器，按协商算法（如 chacha20-poly1305）解密 pcap 中 NewKeys 之后的流量，还原用户名/口令、shell 命令与输出。

## 原理

- OpenSSH 把每个方向的加密状态保存在 `struct sshenc` 中（定义见 `kex.h`）：`char *name; const struct sshcipher *cipher; int enabled; u_int key_len; u_int iv_len; u_int block_size; u_char *key; u_char *iv;`；密钥本身是随机字节，难以直接搜索，但结构体字段有明确约束，适合在堆内存中扫描。
- 扫描判据：name/cipher/key/iv 都是落在 heap 范围内的有效指针；name 指向的字符串等于已知 cipher 名称（如 `chacha20-poly1305@openssh.com`、`aes256-ctr`）；key_len/iv_len/block_size 在合理范围。
- SSH 握手完成后（New Keys），双方用会话密钥加密后续数据；抓包侧只需拿到两个方向的 key/iv 即可解密。chacha20-poly1305 使用 64 字节 key、无独立 IV，MAC 为隐式；AES-CTR/CBC 使用 key + IV + 配套 HMAC 密钥。
- 常见工具缺陷：OpenSSH-Session-Key-Recovery 只提取加密算法密钥，不提取 HMAC 密钥（流加密套件需要）；脚本内置进程名只有 ssh/sshd，而 OpenSSH 10 使用 `sshd-session`；OpenSSH-Network-Parser 不支持 HMAC 配套算法解密。
- 解密后可进一步解析 SSH 消息类型（ServiceRequest/UserAuth/ChannelOpen/ChannelRequest/ChannelData 等），还原认证方式、用户名/口令、执行的命令与终端输出。

## 触发条件

- 能读取 ssh 客户端或 sshd-session 服务端进程内存（root、GDB attach、ptrace 权限、内存镜像/Volatility）。
- 有对应时间段的 pcap，且能确定 SSH 连接的四元组/方向。
- 目标使用 OpenSSH，会话已进入 New Keys 之后的加密阶段。
- 知道或能枚举协商算法；chacha20-poly1305 可直接用 64 字节 key 解密，AES-CTR/CBC 还需 HMAC 密钥。

## 利用步骤

1. 用 Wireshark 过滤 `ssh`，确认版本协商、Key Exchange Init/Reply、New Keys 位置，记录协商的 encryption/MAC 算法与连接四元组。
2. 在客户端或服务端 attach 进程：`sudo gdb attach <pid>`；`info proc mappings` 找 `[heap]` 起止地址。
3. `dump memory heapdump <heap_start> <heap_end>`，得到内存镜像。
4. 用工具或自写脚本扫描 `sshenc`：按 4/8 字节对齐遍历，校验 name/cipher/key/iv 指针落在 heap 范围、name 是已知 cipher、key_len/iv_len/block_size 合理；输出 `{proc_name, key, iv, cipher_name}`。
5. 生成 `key.json`（两个方向各一条），用 `network-parser -p capture.pcap -o output --proto=ssh --popt keyfile=./key.json -s -vvvv` 解密；或按算法自行解密。
6. 解析解密后的 SSH 消息，提取认证用户名/口令、执行的命令、终端输出、文件传输内容。

## PoC

GDB 提取堆：

```bash
sudo gdb attach <pid>
(gdb) info proc mappings
(gdb) dump memory heapdump 0x02445000 0x02501000
(gdb) quit
```

扫描 sshenc（Go 核心思路）：

```go
type sshenc struct {
    Name, Cipher           uintptr
    Enabled, KeyLen        uint32
    IVLen, BlockSize       uint32
    Key, IV                uintptr
}
// 遍历 heapdump；若 Name/Cipher/Key/IV 落在 heap 范围，
// 且 Name 指向的字符串是已知 cipher、KeyLen/IVLen/BlockSize 合理，
// 则输出 key = heap[Key-heapStart : Key-heapStart+KeyLen]。
```

key.json（示意）：

```json
{"cipher_name":"chacha20-poly1305@openssh.com","key":"<128 hex>","iv":""}
{"cipher_name":"chacha20-poly1305@openssh.com","key":"<128 hex>","iv":""}
```

解密：

```bash
python2 -m openssh_network_parser.tools.network_parser \
  -p ./22.pcap --proto=ssh --popt keyfile=./key.json -o ./output -s -vvvv
```

## 变体与关联

- 内存获取方式：GDB dump、Volatility 插件、/proc/<pid>/mem、core dump、VM 快照；进程名需包含 `sshd-session`（OpenSSH 10）。
- 算法：chacha20-poly1305（64 字节 key，无 IV）；AES-CTR/CBC 需同时提取 HMAC 密钥；AES-GCM 的 IV 每帧递增需暴力/推算。
- 工具：OpenSSH-Session-Key-Recovery、OpenSSH-Network-Parser、自研解析器；也可只提取 key 后用 Wireshark/脚本解密。
- 关联：RDP/SMB3/WinRM 流量解密、TLS 私钥解密、内存取证中的会话密钥恢复。

## 检测与防御

- 限制 ptrace（`/proc/sys/kernel/yama/ptrace_scope=1`）、隐藏进程信息（hidepid）、禁止非 root 读取 `/proc/<pid>/mem`；禁用不必要的 core dump。
- SSH 服务以最小权限运行，使用硬件密钥/证书认证并缩短会话生命周期；对高敏感环境使用额外加密隧道。
- 监控异常的 GDB attach、堆 dump、大块内存读取与 key 文件生成；对已捕获 pcap 的解密行为做审计。
- 事件响应方可在获得授权的前提下用该方法还原攻击者 SSH 操作，但需妥善保管内存镜像与密钥材料。
