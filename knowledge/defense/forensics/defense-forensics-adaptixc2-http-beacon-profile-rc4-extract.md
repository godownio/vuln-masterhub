---
id: defense-forensics-adaptixc2-http-beacon-profile-rc4-extract
title: AdaptixC2 HTTP Beacon 配置提取与 RC4 解密：4 字节长度 + 加密 Profile + 16 字节 Key
type: scenario
domain: defense
path: defense/forensics
technique: adaptixc2-http-beacon-profile-rc4-extract
aliases:
- AdaptixC2 HTTP Beacon 配置提取
- AdaptixC2 Profile RC4 解密
- agent.x64 profile 扫描
- 4 字节长度 加密配置 16 字节 key
- AdaptixC2 listener encrypt_key
tags:
- adaptixc2
- c2
- forensics
- malware-analysis
- rc4
- profile
- beacon
- http
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V227
  verified_at: '2026-11-07T06:25:31+08:00'
  notes: 已对照原文 18820 与 img01-12 核对：AgentGenerateProfile 的 encrypt_key 取自 listenerMap 并 Base64 解码、params 经 Packer+RC4 组 [len][cipher][16B key]、config.cpp getProfile 硬编码、profile size 0xA9=169、key 0x124DE 与 Undefined symbol 特征、扫描脚本与解密结果均与原文一致；与既有 Gopher TCP 卡（AES-GCM/msgpack 两级密钥）非同一链，diff 明确。未验证点：PoC 未在本机对真实样本复跑；原文仅以 AdaptixC2 v0.8 为分析环境，非受影响版本区间，未设 affected_versions。
---

## 一句话结论

AdaptixC2 HTTP Beacon 把业务配置以 `[4 字节小端 profile_size][profile_size 字节 RC4 密文][16 字节 RC4 key]` 的结构硬编码在 `config.cpp` 并编译进 Agent；拿到 agent.x64.exe 后按该结构扫描候选偏移、用后 16 字节做 RC4 解密，即可离线还原 C2 回连地址、HTTP 方法、URI、心跳头、User-Agent、kill date、工作时段与 sleep/jitter，无需运行样本。

## 原理

- 服务端生成 Agent 时，`AgentGenerateProfile` 从 listenerMap 取 `encrypt_key`（Base64）并解码为 RC4 key；把 C2 地址/端口、HTTP 方法、URI、心跳头、UA、请求头、页面偏移、kill date、working time、sleep、jitter 等 `params` 打包为 `packedParams`，用 RC4 加密成 `cryptParams`，再组 `profileArray = [len(cryptParams), cryptParams, encryptKey]` 打包成顶层 profile。
- `pl_agent.go` 把该 profile 作为 `-DPROFILE='"..."' -DPROFILE_SIZE=...` 传给 MinGW 编译 `config.cpp`；`config.cpp` 的 `getProfile()` 返回这段静态字符串。
- Agent 端 `AgentConfig` 构造函数：
  ```cpp
  ULONG size = getProfileSize();
  CHAR* ProfileBytes = (CHAR*)MemAllocLocal(size);
  memcpy(ProfileBytes, getProfile(), size);
  Packer* packer = ...;
  ULONG profileSize = packer->Unpack32();
  this->encrypt_key = (PBYTE)MemAllocLocal(16);
  memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
  DecryptRC4(packer->data() + 4, profileSize, this->encrypt_key, 16);
  this->agent_type = packer->Unpack32();
  ```
  即 key 紧跟在密文之后，长度固定 16 字节；解密后再按 Packer 字段顺序读取 `use_ssl`、`servers_count`、地址/端口等。
- 因此样本中同时存在密文、明文 key 与长度字段，属于“对称密钥就地存放”的可离线恢复配置；若样本未加壳/未二次加密，静态扫描即可。

## 触发条件

- 取得 AdaptixC2 HTTP Beacon Agent 样本（agent.x64.exe / agent.x86）或内存镜像，且 Profile 未被额外加密/剥离。
- 知道或能从 AdaptixC2 v0.8 源码确认结构 `[4B size][cipher][16B key]`。
- 纯静态即可；也可在 16 进制编辑器中手工定位 key（文章发现 key 后紧跟静态字符串 `Undefined symbol`，可作为定位特征）。

## 利用步骤

1. 在样本中搜索 `agent.x64`/`agent.x86` 或 `getProfile` 相关字符串，定位 `config.cpp` 生成的 Profile 数据。
2. 从任意偏移尝试读取 4 字节小端 `profile_size`，过滤 20–2048 等合理范围；取后续 `profile_size` 字节为密文、再后 16 字节为 RC4 key。
3. 用 RC4 解密，检查明文是否包含 IPv4、`POST`、URI、User-Agent 等特征；命中即为 Profile。
4. 按字段顺序解析：C2 地址/端口、HTTP 方法、URI、心跳头、UA、请求头、kill date、working time、sleep、jitter。
5. 也可从服务端 listener 数据库的 `encrypt_key`（Base64）交叉验证：`base64.b64decode(key)` 应等于样本中提取的 16 字节 key。

## PoC

```python
import struct, re, binascii, base64, textwrap
from Crypto.Cipher import ARC4

def try_parse(blob, off):
    if off + 4 > len(blob): return None
    size = struct.unpack_from("<I", blob, off)[0]
    if not (20 <= size <= 2048): return None
    enc = blob[off+4:off+4+size]
    key = blob[off+4+size:off+4+size+16]
    if len(key) != 16: return None
    dec = ARC4.new(key).decrypt(enc)
    if re.search(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b', dec) or b"POST" in dec:
        return size, key, dec
    return None

blob = open("agent.x64.exe", "rb").read()
for i in range(len(blob) - 20):
    r = try_parse(blob, i)
    if r:
        size, key, dec = r
        print(f"offset=0x{i:X} size={size} key={binascii.hexlify(key).decode()} key_b64={base64.b64encode(key).decode()}")
        print(textwrap.fill(''.join(chr(b) if 32 <= b < 127 else '.' for b in dec[:256]), 80))
        break
```

## 变体与关联

- **x86/x64**：两种架构结构相同；x86 样本也带同样 key 特征。
- **协议变体**：Gopher TCP / SMB 的 Profile 结构与加密算法不同（Gopher 为 `[16B Listener Key][12B nonce][AES-GCM(msgpack)]`，见关联卡）；不要混用解析脚本。
- **静态特征**：key 后紧跟 `Undefined symbol`，可作为快速定位点；若样本被修改/加壳，特征可能消失。
- **关联**：[[defense-forensics-adaptixc2-gopher-tcp-config-session-key-decrypt]]（同产品 Gopher TCP 配置与会话密钥提取）、[[code-analysis-reverse-windows-remcos-settings-config-extraction]]（另一 C2 的 RC4 配置提取）。

## 检测与防御

- **本卡性质**：恶意样本取证与 C2 配置恢复方法，不是攻击面。
- **防护/检测**：静态扫描 Agent 中的 `Undefined symbol`、16 字节高熵 key 与紧随的密文结构；监控 AdaptixC2 默认/魔改 HTTP Beacon 流量；对 C2 样本做配置提取以还原基础设施。
- **加固**：防守方无法阻止攻击者使用该框架，重点是流量检测、IOC 提取与狩猎；对出站 beacon 的固定间隔、TLS 指纹与异常 URI 做告警。
