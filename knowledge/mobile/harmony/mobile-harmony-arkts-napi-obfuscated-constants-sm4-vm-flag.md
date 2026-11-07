---
id: mobile-harmony-arkts-napi-obfuscated-constants-sm4-vm-flag
title: HarmonyOS ArkTS + NAPI 逆向：混淆常量恢复、密码哈希拼接与 SM4/VM 解密 flag
type: scenario
domain: mobile
path: mobile/harmony
technique: harmony-arkts-napi-obfuscated-sm4-vm
aliases:
- 遥遥领先
- HarmonyOS 逆向
- ArkTS 混淆常量
- NAPI getPasswordTail
- hmos_ctf_2026
- SM4 VM 解密
- bridgeVector
tags:
- harmonyos
- arkts
- napi
- reverse
- obfuscation
- sm4
- vm
- hap
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T01:59:54+08:00'
  notes: 已对照原文“遥遥领先”段与图18/20核对：module.json、ArkTS revealText公式、NAPI getPasswordTail、admin token/bridgeVector/buildCheckSeed、SM4 VM流程与EXPECTED_HASH均一致。未验证点：HAP/SO未实际逆向复跑；sub_0x8B9C/0x8BFC等地址为原文所给；frontmatter无sources/source_url。
---

## 一句话结论

HarmonyOS HAP 的 ArkTS 层用 `revealText()` 混淆常量、Native `libentry.so` 的 NAPI 导出 `getPasswordTail` 隐藏密码哈希后半段；恢复 admin 用户名/哈希/salt 后计算 token，再按 `buildBridgeVector` 与 `buildCheckSeed` 派生 seed，交给 native VM 做 SM4 解密与哈希校验，最后用 ArkTS `decodeProof()` 还原 flag。

## 原理

- HAP 的 `module.json` 给出 `mainElement: EntryAbility`、`pages: $profile:main_pages`；首屏 `pages/LoginPage`，登录成功进入 `pages/Home`。
- `DatabaseUtil.checkLogin()` 有访客分支（隐藏用户名 + `walkin`）和正常分支（用户名 + SHA256 密码哈希）；本地用户表只有 `admin` 与一个密码哈希。
- ArkTS 常量混淆：`step = (index*9 + bias) & 0xff; value = (((dust[index] - step) + 0x100) & 0xff) ^ mask[index % len(mask)]`；按此恢复 `USER_*`、`ADMIN_TAG_*`、`VISITOR_*`、`GUEST_TOKEN_*`、`SALT_*`、`FOLD0/1/2_*`、`TOKEN_TAG_*`。
- `PASSWORD_HASH_PARTS` 只暴露前 32 个 hex 字符；后半段由 native `libentry.so` 的 NAPI 导出 `getPasswordTail`（`sub_0x8B9C`，循环在 `0x8BFC-0x8C34`）按 `HASH_TAIL_PACK ^ mask ^ (0x41 + i*7)` 还原。
- Token：`sha256(username + password_hash + salt)`；案例 `admin`、完整哈希、`hmos_ctf_2026` 得到 admin token。
- `buildBridgeVector(stageTag, pageReady, mirror)`：`token_head=token[:16]`，`source = user|token_head|stageTag|1|len(mirror)`，逐字符 `source[i] ^ user[i%len] ^ mirror[i%len] ^ ((i*17+len(token))&0xff)`，转 hex。
- `buildCheckSeed(token, bridgeHex)`：先 `sha256(token + "|" + admin_tag + "|" + token_tag + bridgeHex[:20])`，再用三段 fold mask（`bridge-open`/`native-layer`/`arkts-stage`）逐轮拼接 `bridgeHex` 切片做 SHA256，取前 48 hex。
- Native `sub_0x6D10` 是 VM：`DERIVE_KEY → BUILD_RK → APPLY_RK_MASK → XOR_STREAM → SM4_DEC → XOR_STREAM → PKCS7 → HASH32/CMP_HASH → BUILD_PROOF`；SM4 round keys 还做了 `^ (0x13579BDF + i*0x01010101)` 与 rotate 的二次掩码。
- ArkTS `decodeProof()` 最终按 `value ^ PROOF_DUST ^ seedChar ^ bridgeChar ^ ((index/2*19 + 0x23)&0xff)` 还原 flag。

## 触发条件

- 目标是 HarmonyOS HAP/APP，ArkTS 代码被混淆，存在 `*_DUST/*_MASK/*_BIAS` 常量数组与 `revealText()`。
- Native `libentry.so` 暴露 NAPI 导出（如 `getPasswordTail`），隐藏部分密钥/哈希。
- 登录/鉴权逻辑包含 token 派生、bridge 向量、seed 派生和 native VM/SM4 解密。
- 能反编译 ArkTS（DevEco/abc 反编译）与 native SO（IDA/Ghidra），并提取常量数组。

## 利用步骤

1. 解包 HAP，读 `module.json` 确定入口与页面路由；反编译 `pages/LoginPage`、`pages/Home`、`DatabaseUtil`、`CTFBridge`、`FlagUtil`。
2. 对每个 `*_DUST/*_MASK/*_BIAS` 套用 `revealText()`，恢复用户名、salt、fold mask、token tag 等明文。
3. 在 `libentry.so` 中定位 NAPI 导出 `getPasswordTail`，按 `HASH_TAIL_PACK ^ mask ^ (0x41+i*7)` 恢复哈希后半段，拼出完整密码哈希。
4. 计算 `token = sha256(user + password_hash + salt)`；构造 `bridgeVector`（注意 `token_head=token[:16]`、`pageReady=1`、`mirror=user`）。
5. 按 `buildCheckSeed` 的三段 fold 哈希计算 seed；从 native 数据中恢复内置 cipher bytes。
6. 复现 native VM 的 `derive_key_material`、`build_round_keys`（含二次掩码）、`xor_stream(base=0x3d, step=0x0b)`、SM4 解密、PKCS7 trim、`hash32x8` 校验。
7. 用 `decodeProof()` 对 proof 做最终 XOR，得到 flag；用 native 的 `EXPECTED_HASH` 验证。

## PoC

```python
import hashlib

def reveal_text(dust, mask, bias):
    out = []
    for i, v in enumerate(dust):
        step = (i * 9 + bias) & 0xFF
        out.append(chr((((v - step) + 0x100) & 0xFF) ^ mask[i % len(mask)]))
    return "".join(out)

def reveal_native_text(packed, seed, step, mask):
    return "".join(chr(v ^ mask[i % len(mask)] ^ ((seed + i * step) & 0xFF))
                   for i, v in enumerate(packed))

admin_user = reveal_text(USER_DUST, USER_MASK, USER_BIAS)          # admin
salt = reveal_text(SALT_DUST, SALT_MASK, SALT_BIAS)                # hmos_ctf_2026
password_hash = PASSWORD_HASH_HEAD + reveal_native_text(HASH_TAIL_PACK, 0x41, 7, HASH_TAIL_MASK)
admin_token = hashlib.sha256((admin_user + password_hash + salt).encode()).hexdigest()

def build_bridge_vector(user, token, stage_tag, page_ready, mirror):
    source = f"{user}|{token[:16]}|{stage_tag}|{1 if page_ready else 0}|{len(mirror)}"
    return "".join(
        f"{(ord(ch) ^ ord(user[i % len(user)]) ^ ord(mirror[i % len(mirror)]) ^ ((i*17 + len(token)) & 0xff)) & 0xff:02x}"
        for i, ch in enumerate(source)
    )

bridge = build_bridge_vector(admin_user, admin_token, "bridge-sync", True, admin_user)
# buildCheckSeed: sha256(token|admin_tag|token_tag|bridge[:20])，再三段 fold mask
# native VM: derive_key_material -> build_round_keys -> xor_stream -> SM4 -> xor_stream -> pkcs7
# 最终 decodeProof() 还原 flag
```

案例恢复的 admin token 为 `8f23ca2211187b27c9b93450be8b5a83253379789fa16946e65fe68f7a057f70`，bridge hex 为 `21350f1aeae99ed1faea899a3e2f1f0e615945e1a692caa5aa809e6c79004d360e12fea2d880`。

## 变体与关联

- 变体：混淆公式可能是 `(dust[i] + bias) ^ mask`、`rol8` 或分段拼接；先识别 `revealText` 的逆运算。
- 变体：NAPI 导出可能用 `napi_register_module_v1` 动态注册，需从导出表/字符串定位函数；哈希尾部可能在 `.rodata` 或运行时解密。
- 变体：native VM 可能是 SM4/AES/XXTEA 的包装；按 opcode 分派识别 `DERIVE_KEY/BUILD_RK/XOR_STREAM/DEC`。
- 关联：[[mobile-harmony-hap-arkts-native-sbox-affine-unicorn]]（ArkTS+native S-box/Unicorn）、[[ctf-reverse-sm4-constant-recognition-little-endian-decrypt]]（SM4 常量识别）、[[ctf-reverse-custom-vm-masked-opcode-inverse-witness-recovery]]（VM 逆向）。

## 检测与防御

- 防御：不要在客户端硬编码密码哈希、salt、token 派生与解密密钥；敏感校验放到服务端。
- 防御：ArkTS 混淆与 native SO 只能提高门槛；关键逻辑应使用服务端签名/认证与完整性校验。
- 检测：HAP 中出现大量 `*_DUST/*_MASK/*_BIAS` 数组、NAPI 导出返回密钥材料、native VM/SM4 解密流程；客户端本地完成完整 flag 校验。
- 响应：发现客户端可恢复密钥后，轮换 token/salt/密钥，改为服务端校验，并审计是否有其他硬编码凭据。
