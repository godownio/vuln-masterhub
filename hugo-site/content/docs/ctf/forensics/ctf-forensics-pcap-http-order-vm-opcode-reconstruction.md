---
id: ctf-forensics-pcap-http-order-vm-opcode-reconstruction
title: 从 pcap 按业务请求顺序还原栈式 VM 后门指令并解密 payload
type: scenario
domain: ctf
path: ctf/forensics
technique: pcap-vm-opcode-reconstruction
tags:
- forensics
- pcap
- http
- vm
- opcode
- backdoor
- payload-decrypt
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V126
  verified_at: '2026-11-06T04:29:39+08:00'
  notes: 已对照原文与图03/04核对：按 HTTP 请求顺序还原 67 条指令、readResource('/payload.enc')、滚动 XOR 解密 (data[i]^key)-i、key=decrypted^55、初始 key=102、writeFile('/tmp/payload_run')、chmod +x、执行、ELF 魔数校验均与原文一致。PoC 未本机复跑；原文未标注组件版本。
url: /docs/ctf/forensics/ctf-forensics-pcap-http-order-vm-opcode-reconstruction/
draft: false
kb_aliases:
- 流量还原 VM 指令
- HTTP 请求序列还原
- payload.enc 解密
- 滚动 XOR 解密
- 栈式 VM 流量取证
---

## 一句话结论

当后门把每条 HTTP 请求映射成栈式 VM 的一个事件时，按时间顺序导出同一会话的请求方法、URI 与 body，就能把分散的头像、评论、登出流量还原成完整指令序列；再从指令序列读出滚动 XOR 解密算法，即可解出 `payload.enc` 得到真正的 ELF 载荷。

## 原理

- 栈式 VM 的事件缓冲按请求到达顺序追加：登录触发清空，头像更新追加整数操作码，评论追加 `[...]` 内的字符串，登出触发解释执行。
- 因此 pcap 中的请求顺序就是 VM 程序顺序；每条请求的 body 字段就是一条指令或一个操作数。
- 文章还原出 67 条指令：先 `readResource('/payload.enc')` 读入字节数组，再以计数器循环执行 `decrypted = (data[i] ^ key) - i & 0xFF`、`key = decrypted ^ 55`，初始 `key=102`，最后 `writeFile('/tmp/payload_run')`、`chmod +x`、执行。
- 逆向 VM 的操作码语义后，指令序列可人工或脚本解释；解密循环的滚动密钥使每字节的 key 依赖上一字节明文，不能简单用固定 XOR 解。
- 解密结果以 `\x7fELF` 开头，确认为 Linux 可执行文件，后续可继续逆向其 C2 与外带逻辑。

## 触发条件

- 拿到包含后门交互的 pcap，且能识别同一会话的登录、业务写入、登出请求。
- 已知或可逆向出 VM 的操作码表与事件注入点。
- `payload.enc` 等加密载荷可从流量、服务器文件或附件取得。

## 利用步骤

1. 用 Wireshark/tshark 过滤 HTTP，按时间排序，跟踪同一 `JSESSIONID` 的 TCP 流。
2. 导出每条请求的方法、URI、body（`tshark -r traffic.pcap -Y http.request -T fields -e frame.time -e http.request.method -e http.request.uri -e http.file_data`）。
3. 按注入点映射事件：`/api/login`→clear、`/api/user/avatar` 的 `emojiAvatarId`→整数操作码、`/api/reviews/add` 的 `content[...]`→字符串、`/api/logout`→执行。
4. 对照 VM 源码/反编译结果翻译操作码（10 读资源、11/12 数组读写、13 XOR、15 写文件、16 执行、17 长度、18 parseInt、21/22 跳转、23/24 加减、25 pick、26 drop）。
5. 从循环指令还原解密算法，写脚本解 `payload.enc`，校验 ELF 魔数。

## PoC

```bash
tshark -r traffic.pcap -Y http.request \
  -T fields -e frame.time -e http.request.method -e http.request.uri -e http.file_data > 1.txt
```

```python
def decrypt_payload(enc_path, out_path):
    data = bytearray(open(enc_path, 'rb').read())
    key = 102
    for i in range(len(data)):
        decrypted = ((data[i] ^ key) - i) & 0xFF
        data[i] = decrypted
        key = decrypted ^ 55
    assert data[:4] == b'\x7fELF'
    open(out_path, 'wb').write(data)
```

## 变体与关联

- 若请求被压缩/分块，先重组 HTTP body 再映射事件。
- 若后门使用其他事件载体（Header、Cookie、分页参数），按实际注入点替换映射规则。
- 关联：[[pentest-c2-java-web-stack-vm-backdoor-business-params]]（VM 后门机制）、[[defense-forensics-godzilla-java-webshell-traffic-decode]]（Java webshell 流量解码）。

## 检测与防御

- 检测：同一会话跨多个业务接口的异常事件序列；头像/评分等数值参数反复出现 1–26；评论内容含 `[...]` 包裹的路径或命令；登出时出现子进程。
- 取证：保留完整 pcap 与服务器上的 `payload.enc`，按请求顺序重建指令流并解释执行。
- 防御：业务组件不解释用户可控指令流；对跨接口的会话事件做关联审计；生产环境移除 analytics/report 后门组件。
