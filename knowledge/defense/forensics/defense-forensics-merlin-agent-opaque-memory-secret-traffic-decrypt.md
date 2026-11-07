---
id: defense-forensics-merlin-agent-opaque-memory-secret-traffic-decrypt
title: Merlin Agent 内存取 OPAQUE 会话密钥：64 位 hex 字符串扫描 + transformers 解密全协议流量
type: scenario
domain: defense
path: defense/forensics
technique: merlin-agent-opaque-memory-secret-traffic-decrypt
aliases:
- Merlin Agent 流量解密
- Merlin 内存密钥
- OPAQUE 会话密钥提取
- gopaque SharedSecret
- C2 内存密钥取证
- jwe,gob-base 解密
tags:
- forensics
- memory
- c2
- merlin
- opaque
- ed25519
- session-key
- traffic-decrypt
- transformers
- jwe
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V255
  verified_at: '2026-11-07T16:00:44+08:00'
  notes: 已对照原文与46张图核对：client.secret两次赋值、gopaque 64位hex共享密钥、内存dmp扫描与transformers试解、HTTP/H2C/SMB/TCP/UDP及多种transformers组合解密截图一致；HTTPS需TLS密钥的边界也已注明，未复跑脚本
---

## 一句话结论

Merlin Agent 在 OPAQUE 身份认证通过后，把协商出的共享密钥以 64 个十六进制字符的字符串形式存放在 `client.secret` 中；对木马进程做内存 dump，用 `[0-9a-fA-F]{64}` 扫出候选串并逐个拿已知密文用 Merlin 的 transformers 链试解，返回非零 UUID 消息的那个串就是会话密钥，之后即可离线解密 HTTP/H2C/SMB/TCP/UDP 各通信环节及不同 transformers 组合下的加密流量。

## 原理

- **两阶段密钥**：Merlin Agent 上线时先用样本配置里的 `psk` 派生预共享密钥（`SHA256(psk)`）加密身份认证流量；认证使用 OPAQUE 协议（项目依赖 `cretz/gopaque`），协商成功后得到新的共享密钥，后续正常通信改用新密钥。只拿到 pcap 无法直接解出后者，必须另找密钥来源。
- **为什么内存里有可匹配特征**：Merlin 项目把 OPAQUE 协商后的 `SharedSecret` 通过 `fmt.Sprintf("%+v", ...)` 转成字符串赋给 `client.secret`；gopaque/kyber 的标量字符串表现为 64 个十六进制字符（文章按“Ed25519 签名长度固定 64 字节”解释其长度固定，脚本实测 `len` 为 64）。因此进程内存中会出现连续的 `[0-9a-fA-F]{64}` 字符串，且同一密钥可能因字符串化/副本出现多次。
- **候选筛选的 oracle**：内存里 64 位 hex 串很多，不能凭外观判断。Merlin 的 `transformers` 链（如默认 `jwe,gob-base`）按配置顺序逐层 `Deconstruct`，只有正确密钥才能解出 `merlin-message` 的 `Base` 结构；脚本以 `Base.ID != 00000000-0000-0000-0000-000000000000` 作为命中判据，命中即锁定密钥。
- **transformers 链**：Merlin 支持 `aes`、`base64-byte`/`base64-string`、`gob-base`/`gob-string`、`hex-byte`/`hex-string`、`jwe`、`rc4`、`xor` 等组合；解密必须按样本配置的相同顺序应用。默认 `jwe,gob-base` 的载荷通常以 `eyJhbGciOiJQQkVTMi1IUzUxMitBMjU2S1ci...` 开头（JWE 头）。
- **适用范围**：文章的验证覆盖 HTTP、H2C 上线通信与 SMB、TCP、UDP 跳板通信，以及 `aes,gob-base`、`base64-string,gob-base`、`hex-byte,gob-base`、`hex-string,gob-base`、`gob-string,gob-base`、`rc4,gob-base`、`xor,gob-base` 等组合，均能用同一方法解密。前提是拿到未加密传输的载荷（HTTP/H2C）或在 TLS 层之外提取载荷；HTTPS 流量需先取得 TLS 会话密钥。
- **取证价值**：可从流量还原上线/心跳、攻击者下发的命令、文件传输、Socks 代理等业务内容，弥补“只有加密流量无法定性”的缺口。

## 触发条件

- 已捕获 Merlin Agent 的加密流量（HTTP、H2C、SMB、TCP、UDP 等；非 TLS 或已取得 TLS 解密条件），并能导出各会话的加密载荷。
- 能获取木马进程的内存转储（ProcessHacker/System Informer 等），且进程在 dump 前已完成 OPAQUE 认证（内存中存在协商后的 `client.secret`）。
- 知道样本的 transformers 配置顺序（默认 `jwe,gob-base` 可从流量特征/配置提取）。
- 有 Merlin 的 `merlin-message`/transformers 库源码用于构建解密函数（版本需与样本匹配）。

## 利用步骤

1. 从流量中提取加密载荷：HTTP/H2C 可用 Wireshark 的“导出对象”导出；SMB/TCP/UDP 按协议手工提取会话数据，整理为每行一个载荷的文本文件。
2. 用 psk 派生预共享密钥：`SHA256(psk)` 的原始字节（脚本中先 hex 编码再 `hex.DecodeString` 还原）作为 secret，先循环解密认证阶段载荷；遇到解不开的载荷，记录其位置，后续用协商密钥处理。
3. 对 Merlin Agent 进程做内存 dump（如 ProcessHacker/System Informer 的 dump 功能），得到 `.dmp` 文件。
4. 在 dump 中用正则 `[0-9a-fA-F]{64}` 提取所有 64 位十六进制字符串并去重。
5. 对每个候选密钥，调用 Merlin 的 `DeconstructMessages(已知密文, secret, transforms)`；若返回的 `Base.ID` 不是全零 UUID，则该候选是协商后的会话密钥。
6. 用该密钥解密认证之后的全部载荷，输出 `ID/Type/Payload/Delegates`，还原攻击者指令与回显。
7. 若默认 `jwe,gob-base` 解不开，按样本配置换用其他 transformers 组合或调整顺序重试。

## PoC

预共享密钥与候选扫描（Go 骨架，依赖 Merlin 的 transformers / merlin-message 源码）：

```go
// 认证前：secret = SHA256(psk) 的原始 32 字节
preSecret, _ := hex.DecodeString(hashSHA256([]byte("merlin")))
for i, data := range payloads {
    if _, err := DeconstructMessages([]byte(data), preSecret, transforms); err != nil {
        payloads = payloads[i:] // 从这里开始是认证后的流量
        break
    }
}

// 认证后：在内存 dump 中找 64 位 hex 字符串并试解
dump, _ := os.ReadFile("merlinAgent.dmp")
re := regexp.MustCompile(`[0-9a-fA-F]{64}`)
for _, cand := range dedup(re.FindAllString(string(dump), -1)) {
    base, err := DeconstructMessages([]byte(payloads[0]), []byte(cand), transforms)
    if err == nil && base.ID.String() != "00000000-0000-0000-0000-000000000000" {
        fmt.Println("session secret:", cand)
        break
    }
}
```

`transforms` 按样本配置拆分，例如 `strings.Split("jwe,gob-base", ",")`；`DeconstructMessages` 需按顺序为每层注册对应 transformer（jwe、gob、aes、base64、hex、rc4、xor），并用 `gob.Register` 注册 `merlin-message` 的 `opaque.Opaque`、`jobs.Command`、`jobs.FileTransfer` 等类型。

## 变体与关联

- 变体：若内存中没有匹配到可用密钥，可结合进程内存页权限（RW 堆/数据段）缩小范围，或从崩溃转储/分页文件中恢复更早的密钥副本。
- 变体：transformers 非默认组合时，先通过载荷特征判断最外层编码（JWE 头、base64/hex 字符集、gob 二进制），再按配置顺序重放；文章已用多种组合验证该方法通用。
- 关联：[[defense-forensics-cobaltstrike-memory-beacon-session-key-collision]]（同样在无密钥文件时从 C2 进程内存提取会话密钥，用已知密文做碰撞验证；CS 是 16 字节候选，Merlin 是 64 位 hex 字符串候选）。
- 关联：[[defense-forensics-core-dump-secret-extraction]]（内存/core dump 中提取密钥与凭据的通用方法）。
- 关联：[[defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt]]、[[defense-forensics-valleyrat-c2-6666-xor-traffic-decrypt]]（其他 C2 的流量解密思路）。

## 检测与防御

- **取证侧**：该方法是授权应急响应/恶意样本分析手段；dump 与 pcap 按证据链保存，避免在非授权环境使用。
- **检测思路**：在内存取证中，若发现 Merlin 相关模块/字符串，优先搜索 `client.secret`、`jwe`、`gob-base`、`merlin`、`opaque` 等线索；对 64 位 hex 串的批量试解可作为自动化流程。
- **木马作者可能的规避**（供防御方评估检测盲区）：不要把会话密钥以连续可打印字符串形式长期驻留内存，改用原始字节、分片/加密存储、`mlock`/`madvise` 并主动清零；这会提高内存扫描难度，但不是根本防护。
- **网络侧**：对 C2 流量做 JA3/JA4、载荷格式与心跳周期检测；即使无法解密，也可通过流量元数据识别 Merlin 的 HTTP/H2C/SMB/TCP/UDP 多通道特征。
- **边界**：HTTPS/TLS 封装的流量无法仅靠本方法解密，需要 TLS 密钥或端点内存中的 TLS 会话材料；文章验证的是非 TLS 的 HTTP/H2C 与跳板原始协议流量。
