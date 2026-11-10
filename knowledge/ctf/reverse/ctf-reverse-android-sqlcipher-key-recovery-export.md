---
id: ctf-reverse-android-sqlcipher-key-recovery-export
title: SQLCipher 加密库密钥恢复：应用内多层编码藏 key 后 PRAGMA 解密导出
type: scenario
domain: ctf
path: ctf/reverse
technique: sqlcipher-key-recovery-export
aliases:
- SQLCipher 解密
- sqlcipher_export 导出
- 加密数据库 key 恢复
tags:
- ctf
- reverse
- android
- sqlcipher
- sqlite
- database
severity: low
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-26
  verified_at: '2026-11-08T14:21:09+08:00'
  notes: 已对照原文核对：三层 base64 图16 得 AVENTURINE、图17 sqlcipher CLI PRAGMA key+sqlcipher_export 导出、图18 flag 表含 blowfish key、图19 Frida hook 得 flag，链路完整可复现；与 mobile-android-sqlcipher-static-key-derivation 触发条件不同（key 藏 INSERT 三层 Base64 而非静态常量派生）；未验证点：未实际运行 sqlcipher
---

# SQLCipher 加密库密钥恢复：应用内多层编码藏 key 后 PRAGMA 解密导出

## 一句话结论

应用用 SQLCipher（`net.sqlcipher`）加密 SQLite 库且 key 校验函数返回空串导致无法直接运行时，key 往往藏在应用自身数据中——本题藏在 `onCreate` 插入语句的 INFO 字段里，经三层 Base64 解码得到；随后用 SQLCipher 命令行 `PRAGMA key` 验证并 `sqlcipher_export` 导出明文库，即可拿到后续加密算法所需的 key/密文。

## 原理

SQLCipher 对整库文件加密，`getWritableDatabase(password)` 以口令派生页密钥；口令错误时打开即报错，这是题目防一键运行的常用手法。而应用初始化时必须往库里写入种子数据（`onCreate` 的 INSERT），这些种子值属于应用资产、静态可见——本题三条记录的 INFO 字段（如 `VVZaYVJsUn`）逐层 Base64 解码后得到明文口令 `AVENTURINE`，另一条记录的解码结果（"Three decryptions"）则是提示。拿到口令后，SQLCipher 支持 `PRAGMA key = '口令'` 后用 `ATTACH DATABASE ... KEY ''` + `SELECT sqlcipher_export('plaintext')` 把解密内容完整复制到明文库，等效于离线解密整库，无需 hook 运行时。

## 触发条件

- APK 内嵌或随附 `.db` 文件打开为非常规 SQLite 头（SQLCipher 加密特征：文件头非 `SQLite format 3`）；
- Java/native 层可见 `net.sqlcipher`/`SQLiteDatabase.loadLibs` 调用；
- 应用数据中存在多层编码字符串（Base64 嵌套、资源文件、raw 资源等）候选口令。

## 利用步骤

1. jadx 跟踪 `dB`/`dH` 类，确认 SQLCipher 与库名 `bangbu.db`，注意到 `b.c()` 返回空串（防运行）；
2. 从 `onCreate` 的 INSERT 语句提取 INFO 字段值，CyberChef 递归 Base64 解码三次得到 `AVENTURINE`；
3. SQLCipher 3.8.x 命令行验证并导出：
   `PRAGMA key = 'AVENTURINE';`
   `ATTACH DATABASE 'plaintext.db' AS plaintext KEY '';`
   `SELECT sqlcipher_export('plaintext');`
   `DETACH DATABASE plaintext;`
4. 打开 plaintext.db 得到 Blowfish key `H4iJkLmNoPqRsTuV` 及加密密文与提示；
5. 后续用 Frida hook DESHelper.encrypt 输入任意格式合规字符串，直接拿到加密结果作为 flag。

## PoC

见利用步骤中 SQLCipher 导出命令序列（PRAGMA key + sqlcipher_export）。

## 变体与关联

- key 也可能藏在 raw 资源、so 字符串、protobuf/JSON 配置中，思路同：应用必须自持解密其资产的能力；
- 自定义加密 SQLite（非 SQLCipher）场景见 ctf/reverse 下 appview_cache.db 系列卡；
- Frida hook 加密函数直接取密文的绕过手法与 gdb-blackbox 逐字节爆破卡互补。

## 检测与防御

- 教学要点：SQLCipher 保护的是库文件本身，key 与库同置一处时保护即失效；应把 key 放入服务端或 keystore；
- 防御侧：SQLCipher 的口令不应能从静态资产推导；`sqlcipher_export` 导出明文库后注意明文落地风险。
