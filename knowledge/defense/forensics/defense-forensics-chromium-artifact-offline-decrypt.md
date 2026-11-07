---
id: defense-forensics-chromium-artifact-offline-decrypt
title: Chromium 数据离线解析：密钥静态注入、前缀分派与七类数据还原
type: scenario
domain: defense
path: defense/forensics
technique: chromium-artifact-offline-parse
aliases:
- BrowserDataRestore
- 浏览器取证
- Cookies 离线解密
- Login Data 解析
- Chromium 时间戳转换
- 七类浏览器数据提取
tags:
- windows
- forensics
- chromium
- sqlite
- cookie
- password
- artifact-parsing
- offline
cve: []
severity: medium
confidence: high
affected_versions: Chromium v10/v11/v20 数据格式（Chrome 80+ / Chrome 127+）
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V78
  verified_at: '2026-11-05T16:28:51+08:00'
  notes: 已对照原文与7张图核对：v10/v11/v20 前缀分派、GCM 取 data[3:15]/data[15:]、Chromium 1601 epoch 微秒换算、七类数据表与排序策略、扩展三路径回退均一致；图05 佐证 BrowserDataRestore 输出 password.json。未验证点：未实际运行离线解析；frontmatter 无 sources/source_url。
---

## 一句话结论

把目标机器导出的 32 字节主密钥静态注入恢复工具，按 `v10/v11/v20` 前缀分派 AES-GCM/CBC 解密，并以只读方式解析 Chromium 的 SQLite 与 JSON 数据，即可在任意分析机离线还原密码、Cookie、历史、下载、书签、信用卡与扩展七类数据。

## 原理

- 密钥与数据分离采集：`keys.json` 中的 base64 密钥直接解码为 `[]byte`，恢复过程不再调用 DPAPI/ABE，因此不受目标机器/用户绑定限制，只要密钥与数据同源即可跨主机解密。
- Chromium 加密字段统一为 `版本前缀(3B) + 密文`，按前缀分派：
  - `v10`：key 为 32 字节时用 AES-256-GCM（Windows）；否则用 AES-128-CBC（macOS/Linux）。
  - `v11`：Linux keyring 派生，用 AES-128-CBC。
  - `v20`：Chrome 127+ ABE，用 AES-256-GCM。
  - 无前缀：老版本明文，原样返回。
- GCM 布局为 `前缀(3B) ‖ nonce(12B) ‖ 密文 ‖ tag(16B)`；解密调用 `aead.Open(nil, data[3:15], data[15:], nil)`。密钥与数据不匹配时返回 `cipher: message authentication failed`，工具应统计失败数并告警，不能静默输出空值。
- Cookie 明文在新版本中带 32 字节 `SHA256(host_key)` 前缀，需要剥离后才能得到真实值；密码字段直接 UTF-8。
- Chromium `base::Time` 是自 `1601-01-01 UTC` 起的微秒数；转换为 Unix 时间需减去 `11644473600000000` 微秒，再 `time.UnixMicro`。
- 七类数据来源：
  - password：`Login Data` → `logins`，解密 `password_value`；
  - cookie：`Network/Cookies`（回退 `Cookies`）→ `cookies`，解密并剥离 host 哈希；
  - history：`History` → `urls`；
  - download：`History` → `downloads`；
  - bookmark：`Bookmarks` JSON，递归 `roots.*.children`；
  - creditcard：`Web Data` → `credit_cards`，解密 `card_number_encrypted`；
  - extension：`Secure Preferences` 的 `extensions.settings`，过滤系统组件。
- 扩展解析要依次尝试 `extensions.settings`、`settings.extensions`、`settings.settings` 三个 JSON 路径；跳过 `location=5/10` 的系统组件；启用态优先看 `disable_reasons`（空数组=启用），否则回退 `state==1`。

## 触发条件

- 已从目标机器获得浏览器主密钥（v10/v11/v20）与数据文件副本（含 `-wal`/`-shm` 更佳）；
- 分析机可运行只读 SQLite 解析逻辑，不需要目标机器的 DPAPI/ABE 环境；
- 数据文件未损坏，密钥与数据来自同一浏览器安装/用户配置；
- 取证场景需保证副本哈希与证据链。

## 利用步骤

1. 读取 `keys.json`，解析 `v10/v11/v20` 三类密钥（base64 → `[]byte`），校验长度。
2. 识别数据目录布局：单浏览器 profile 目录或 archive 布局；定位 `Default/Network/Cookies`、`Default/Login Data`、`History`、`Bookmarks`、`Web Data`、`Secure Preferences`。
3. 以只读方式打开 SQLite（纯标准库手写解析或 SQLite 只读驱动），按类别执行查询。
4. 对每个加密字段调用 `decryptValue`：按前缀分派算法，GCM 取 `data[3:15]` 为 nonce、`data[15:]` 为密文；失败计数并告警。
5. Cookie 解密成功后，若明文前 32 字节为 `SHA256(host_key)` 则剥离；按 `creation_utc/expires_utc` 转换时间。
6. 书签递归遍历 `roots.*.children`；扩展按三个 JSON 路径回退，过滤系统组件，确定启用态。
7. 按类别输出 `password.json`、`cookie.json`、`history.json`、`download.json`、`bookmark.json`、`creditcard.json`、`extension.json`；排序策略：password/cookie/bookmark 按创建时间降序，history 按访问次数降序，download 按开始时间降序。
8. 在报告中记录解密成功/失败数量、数据文件哈希与来源，便于证据链核对。

## PoC

```go
func decryptValue(mk MasterKeys, ciphertext []byte) ([]byte, error) {
    switch {
    case bytes.HasPrefix(ciphertext, []byte("v10")):
        if len(mk.V10) == 32 {
            return aesGCMDecrypt(mk.V10, ciphertext)  // Windows v10
        }
        return aesCBCDecrypt(mk.V10, ciphertext)      // macOS/Linux v10
    case bytes.HasPrefix(ciphertext, []byte("v11")):
        return aesCBCDecrypt(mk.V11, ciphertext)      // Linux v11
    case bytes.HasPrefix(ciphertext, []byte("v20")):
        return aesGCMDecrypt(mk.V20, ciphertext)      // Chrome 127+ ABE
    default:
        return ciphertext, nil                        // 老版本明文
    }
}

func aesGCMDecrypt(key, data []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    aead, _ := cipher.NewGCM(block) // NonceSize = 12
    return aead.Open(nil, data[3:15], data[15:], nil)
}

const chromiumEpochOffsetMicros int64 = 11644473600000000
// t := time.UnixMicro(epoch - chromiumEpochOffsetMicros).UTC()
```

## 变体与关联

- 数据文件可能带 `-wal`/`-shm`，离线打开时要把三个文件放在同一目录，才能读到最新事务。
- 多 profile（Default、Profile 1、Profile 2）需要分别解析并标注 `_profile`。
- v11/Linux 与 macOS 的 v10 是 AES-CBC，不要用 GCM 分支硬解。
- 关联卡片：[[pentest-privilege-escalation-chromium-v10-dpapi-credential-decrypt]]、[[pentest-privilege-escalation-chrome-v20-abe-ielevator-injection]]、[[defense-forensics-locked-browser-sqlite-handle-duplication]]。

## 检测与防御

- 检测：离线解析本身在分析机进行，主机侧难以直接发现；应重点检测前期的密钥导出与数据复制行为（DPAPI 调用、句柄复制、浏览器数据库读取）。
- 防御：启用 App-Bound Encryption（v20）；不保存密码或使用密码管理器；2FA/硬件密钥；浏览器退出时清理 Cookie；对浏览器配置目录做 ACL 与 EDR 监控；定期轮换可能已泄露的凭据。
- 注意：只要攻击者同时拿到密钥与数据，离线解密不可阻止；防御重点是阻止“同源获取”并缩短凭据有效期。
