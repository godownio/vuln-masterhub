---
id: ctf-forensics-antsword-rot13-reverse-encoder-traffic-decode
title: 蚁剑自定义编码器流量按编码器逐段还原：ROT13 与 Reverse（按字符倒序）两层解码
type: scenario
domain: ctf
path: ctf/forensics
technique: antsword-custom-encoder-traffic-decode
tags:
- ctf
- forensics
- traffic-analysis
- webshell
- antsword
- encoding
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-28
  verified_at: '2026-11-08T14:59:30+08:00'
  notes: 已对照原文核对：图01-05 证实流10 ROT13、流12 reverse，证据相符
url: /docs/ctf/forensics/ctf-forensics-antsword-rot13-reverse-encoder-traffic-decode/
draft: false
kb_aliases:
- 蚁剑流量分析
- AntSword 编码器解码
- rot13 webshell 流量还原
- reverse 字符倒序解码
---

## 一句话结论

当蚁剑流量使用自定义编码器时，抓包中的 POST/响应数据呈随机字符形态，但只要在客户端配置中确认编码器链（本例为 ROT13 与 Reverse 两层），把 payload 逐段送入 CyberChef 按相同顺序解码即可还原出攻击者执行的每一条命令（如 cut -c N /flag 逐字符切出 flag）。

## 原理

- 蚁剑的编码器是可叠加的：客户端把待发送数据先经过配置的编码函数（如 ROT13 仅旋转字母、Reverse 按字符倒序），再拼进 HTTP 请求；响应同样经过编码后回传。
- 因此流量侧看到的乱码并非加密，而是可逆编码——ROT13 只影响 a-zA-Z（数字与符号原样保留，如 `7b68ec1230p` 中数字不变），Reverse 则把每个数据段整体倒序（`galf/ ... cuc - c` 倒序后即 `cut -c ... /flag`）。
- Wireshark 的「追踪 TCP 流」按流号分割会话，本题中不同流承载不同编码器与命令段：流 10 为 ROT13 段，流 12 为 Reverse 段。

## 触发条件

- 已获得含蚁剑 C2 会话的 pcap；
- 已知或可猜测客户端使用的编码器配置。

## 利用步骤

1. Wireshark 逐条追踪 TCP 流（流 10、流 12），复制其中的 payload 文本。
2. 对 ROT13 段：CyberChef Recipe 选 ROT13，Amount=13，勾选 Rotate lower/upper case chars、不旋转数字，得到形如 `7068rp1230c` 的命令片段。
3. 对 Reverse 段：CyberChef 选 Reverse By Character，得到 `cut -c 10 /flag`、`cut -c 9 /flag` 等明文命令序列。
4. 按各命令 `cut -c N /flag` 的 N 把每条输出字符按位置拼回，还原完整 flag/敏感数据。

## PoC

无 PoC（纯流量解码流程）。

## 变体与关联

- 编码器可换成 base64、chr、自定义异或等，解码思路相同：先在客户端确认编码链，再在 CyberChef 按逆序堆叠对应 Operation。
- 与常见 webshell 流量识别（蚁剑默认 base64 特征、请求体分段）属于同一分析范式。

## 检测与防御

- 流量侧可对 HTTP POST 中高频出现且解码后含系统命令特征（cut/ls/cat 等）的会话告警；
- 主机侧限制 Web 进程对 flag 类敏感文件与 cut 等工具的访问；部署 RASP 检测 exec 参数拼接。
