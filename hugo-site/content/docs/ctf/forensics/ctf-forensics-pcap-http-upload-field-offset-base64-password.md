---
id: ctf-forensics-pcap-http-upload-field-offset-base64-password
title: PCAP 里 HTTP 上传字段的 base64 密码解不开：按上传报文格式定位真实起始偏移，去掉前 N 字符再解
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-http-upload-field-offset-base64-password
tags:
- ctf
- forensics
- pcap
- http
- base64
- upload
- password-recovery
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-3W3
  verified_at: '2026-11-08T19:35:22+08:00'
  notes: 已对照原文核对；本次核对未读取图片；原文第 9 题为追踪 HTTP 第 26 条流找到 flag.php、litctf= 字段 URL 解码得 base64、去前两位后作密码解密，卡内字段前缀污染导致相位错位的判定与 [2:] 对齐方法一致；具体密码与 flag 仅在截图中未验证
url: /docs/ctf/forensics/ctf-forensics-pcap-http-upload-field-offset-base64-password/
draft: false
kb_aliases:
- 流量包取压缩包密码
- 上传参数 base64 偏移
- litctf= 字段解密
- HTTP 流定位 flag.php
- 追踪 HTTP 流找密码
---

## 一句话结论

流量包里追到一个加密压缩包（或加密脚本）却缺密码时，密码往往就在同一个 PCAP 的上传/提交请求里：某个字段（如 `litctf=`）的值看着是 base64，直接解码却报错——因为**报文字段里混入了上传格式的前缀**（表单序列化、文件名/类型标记、长度头），按格式对齐、把开头多余的两三个字符去掉再解，就能得到压缩包口令。

## 原理

- 浏览器/客户端提交文件或表单时，字段值常被包装：`multipart/form-data` 有 `name=`/`filename=`/`Content-Type` 与空行分隔；自定义序列化（如 `key=值&`、长度前缀、类型前缀）会在真值前加标记。抓包看到的是**整个字段串**，不是纯数据。
- base64 解码对"多出来的前缀"极其敏感：多 1~2 个字符会让整串长度不再是 4 的倍数、字符相位整体错位，于是解码要么抛异常、要么输出不可读。分析者很容易误判为"这不是 base64"或"密码在别处"。
- 正确的定位方式不是猜，而是**看报文结构**：找到字段边界（`&`、`\r\n`、`"`、长度头），确定"值"从第几个字节开始；本题上传格式规定数据从第 3 位开始，因此取到的 base64 串要 `[2:]` 去掉前两个字符。
- 判断对齐是否正确的检查点很明确：去掉前缀后长度 `% 4 == 0`、字符全在标准表内、补 `=` 后能解出可打印文本。三者同时满足即对齐成功。
- 为什么先追 HTTP 而不是 TCP：文件在 TCP 流里是分散的多个段，`Follow TCP Stream` 看到的是拼接后的原始字节（含大量二进制噪声），而 `Follow HTTP Stream` 会按报文边界重组，请求行/头/字段一目了然——本题正是在第 26 条 HTTP 流里直接看到 `flag.php` 与那个字段。

## 触发条件

- 有完整或较完整的 PCAP，且其中包含文件上传/表单提交类 HTTP 请求。
- 提取出的附件/对象是加密的（ZIP/7z/RAR、加密脚本、加密 flag 文件），缺口令。
- 上传字段的值具有 base64 特征（字符集、末尾 `=`、长度接近 4 的倍数）。
- 已知或可推断该客户端的上传序列化格式（报文里能直接看出前缀形态）。

## 利用步骤

1. 先用 `binwalk`/`foremost`/Wireshark「导出 HTTP 对象」把附件与可疑脚本全部落地，确认哪一个是加密的、需要什么口令。
2. 在 Wireshark 里 `统计 → 会话/端点` 找出流量集中的 TCP 会话，然后逐条「追踪 HTTP 流」（而不是 TCP 流）；重点找上传（POST、`multipart/form-data`）与脚本访问。
3. 定位含口令的字段：先按关键字（题目前缀、`pass`、`pwd`、`key`、`flag`）搜索流内容，再读该字段的完整值。
4. 按报文格式确定值的真实起点：去掉 `name=`、`filename=`、长度头等前缀；不确定就依次试 `[0:]`、`[1:]`、`[2:]`、`[3:]`，用"能解出可打印文本"判定。
5. base64 解码（必要时补 `=` 对齐），得到明文口令；若解出仍是乱码，再试 URL 解码 → base64 的双层顺序。
6. 用口令解压/解密先前提取的对象，得到 flag。

## PoC

```bash
# 1) 落地所有 HTTP 对象，找出加密附件
tshark -r capture.pcapng --export-objects http,http_objs -q
binwalk -eM http_objs/* 2>/dev/null

# 2) 只看 HTTP 流，定位上传/提交请求
tshark -r capture.pcapng -Y "http.request" -T fields -e frame.number -e http.request.method -e http.request.uri
tshark -r capture.pcapng -q -z follow,http,ascii,26     # 第 26 条 HTTP 流
```

```python
import base64

value = "<从流里取到的字段值>"
for skip in range(0, 5):
    s = value[skip:]
    s += "=" * (-len(s) % 4)
    try:
        pt = base64.b64decode(s, validate=True).decode("utf-8")
    except Exception:
        continue
    if pt.isprintable():
        print(f"skip={skip} -> {pt}")
```

```text
# 本题的判定过程（语义）
字段值形如： <2 字符格式前缀> + base64(密码)
直接解码失败 -> 看上传格式规定数据从第 3 位开始 -> 去掉前 2 字符 -> 解码成功得口令
用该口令解密 flag.php 的加密体 -> flag
```

## 变体与关联

- 变体（前置是 URL 编码）：字段值先 URL 解码（`%2B`、`%3D` 还原）再 base64，顺序搞反会一直失败；本题正是"先 URL 解码得到 base64，再去掉前两位"。
- 变体（长度头而非固定偏移）：前缀是 2/4 字节长度字段（二进制协议），需按长度值切出真值，而不是盲删字符。
- 变体（口令在别的协议）：SMTP/FTP/DNS 隧道里的口令提取思路相同——先按协议边界重组，再处理"值 ≠ 纯数据"。
- 关联：[[ctf-forensics-pcap-custom-base64-tcp-protocol]]（自定义 base64 协议的流量还原）、[[ctf-forensics-pcap-multicast-base64-password-aes-zip]]（口令藏在流量 + 加密压缩包的另一条链）、[[ctf-forensics-http-range-fragment-reassembly-sqlcipher]]（HTTP 分片重组后解密）。
- 边界：PCAP 被截断或上传请求不在捕获范围内时无解；若附件是伪加密而非真加密，应先修 ZIP 位标志而不是找口令。

## 检测与防御

- 说明：本条属 CTF 流量取证与口令恢复方法。
- 防御侧价值：真实事件响应中，攻击者常把凭据以 base64 放在上传/回连报文里；按"协议边界 → 编码层 → 明文"的顺序还原，比全文 `strings` 更可靠。
- 管控建议：出口侧对含超长 base64 字段的上传/请求体做审计与告警；不要在明文 HTTP 里传输任何凭据（本题的密码若走 TLS 就无法这样获取）。
