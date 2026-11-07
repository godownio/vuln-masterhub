---
id: mobile-android-allowbackup-adb-backup-restore-account-takeover
title: Android allowBackup=true + adb backup/restore：导出应用数据并恢复登录态
type: scenario
domain: mobile
path: mobile/android
technique: android-allowbackup-adb-backup-restore-account-takeover
aliases:
- allowBackup 数据导出
- adb backup 应用数据
- adb restore 登录态恢复
- Android 备份配置错误
- 免密登录他人账号
tags:
- android
- allowbackup
- adb
- backup
- misconfiguration
- account-takeover
- mobile
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V122
  verified_at: '2026-11-06T04:17:21+08:00'
  notes: 已对照原文与截图核对：Manifest allowBackup=true、adb backup -noapk 生成 .ab、删除数据后 adb restore 恢复登录态、另一台设备恢复他人账号均与图文一致。未验证点：未在真机复跑 adb backup/restore；原文未给出具体 Android 版本。
---

## 一句话结论

Android 应用把 `android:allowBackup="true"` 且未排除敏感数据时，攻击者可用 `adb backup -noapk <包名> -f backup.ab` 导出应用数据（shared_prefs、数据库、文件），再用 `adb restore` 在另一台设备/重装后恢复，从而在不知道密码的情况下恢复登录态、接管账号。

## 原理

- `allowBackup` 控制应用是否参与 Android 备份框架；为 `true` 时，`adb backup` 可以导出应用私有目录（`shared_prefs`、`databases`、`files`、`cache` 中可备份部分）而无需 root。
- 很多应用把登录 token、Cookie、用户配置、加密数据库密钥等存在 `SharedPreferences`/SQLite 中；备份文件（`.ab`）包含这些数据。
- `adb restore` 把 `.ab` 内容写回应用数据目录；应用启动后读到原账号 token/session，直接进入已登录状态。攻击者可在自己的设备上恢复受害者备份（若拿到 `.ab`），或诱导用户在“备份/迁移”场景导出。
- 为什么可行：备份是系统级功能，默认信任应用声明的 `allowBackup`；应用没有用 `android:fullBackupContent`/`dataExtractionRules` 排除敏感文件，也没有把 token 绑定设备/Keystore。
- 影响：账号接管、隐私数据泄露、绕过登录/二次验证；若备份含数据库密钥，还可解密本地数据。

## 触发条件

- `AndroidManifest.xml` 中 `android:allowBackup="true"`（或未显式设置且默认允许）。
- 应用把敏感数据（token、Cookie、密码、数据库密钥）存放在可备份目录。
- 攻击者能物理/ADB 访问设备（USB 调试已授权）或拿到导出的 `.ab` 文件；Android 版本仍支持 `adb backup`（新版本已弃用/受限，但旧设备/定制 ROM 常见）。
- 备份未加密或口令可获取。

## 利用步骤

1. 反编译/解包 APK，检查 `AndroidManifest.xml` 的 `allowBackup`、`fullBackupContent`、`dataExtractionRules`。
2. 连接设备（USB 调试授权），执行：
   ```bash
   adb backup -noapk com.example.app -f app_backup.ab
   ```
   在设备上确认备份；检查 `.ab` 文件大小是否 > 0。
3. 在另一台设备/重装后的设备上安装同版本应用，执行：
   ```bash
   adb restore app_backup.ab
   ```
4. 启动应用，观察是否直接进入已登录状态/可访问账号数据。
5. 若 `.ab` 被加密，尝试从应用/设备获取备份口令，或分析备份格式；必要时用 `abe`/`android-backup-extractor` 解包查看内容。
6. 记录证据（manifest、备份文件哈希、恢复后界面），评估影响范围。

## PoC

```bash
# 1) 导出（需设备授权 USB 调试）
adb backup -noapk com.example.app -f app_backup.ab
ls -l app_backup.ab

# 2) 在另一台设备/重装后恢复
adb restore app_backup.ab

# 3) 可选：解包 .ab 查看内容（android-backup-extractor）
java -jar abe.jar unpack app_backup.ab app_backup.tar
tar -tf app_backup.tar | head
```

说明：PoC 为原文流程的结构化复现，未在本机执行；原文通过 `adb backup` 导出 `.ab`，删除应用数据后 `adb restore` 直接恢复登录态，甚至在另一台未安装过该应用的手机上登录他人账号。

## 变体与关联

- 变体（备份规则）：`fullBackupContent` 包含/排除文件、`dataExtractionRules`（Android 12+）、`backupAgent` 自定义；配置不当仍可能泄露。
- 变体（获取方式）：物理接触 + ADB、恶意充电桩/调试桥、云备份账号接管、应用内“导出/迁移”功能。
- 变体（敏感数据）：SharedPreferences 中的 token、SQLite 中的会话、Keystore 别名、加密数据库密钥。
- 关联：[[mobile-android-exported-activity-unauth-changepassword-phishing]]（同属 Android 配置错误）；[[mobile-android-spyware-clouddisk-contact-sms-photo-exfil]]（数据窃取类恶意应用）；[[mobile-android-sqlcipher-static-key-derivation]]（本地数据库密钥）。
- 边界：`allowBackup=false`、备份规则排除敏感文件、Android 新版本限制 `adb backup`、备份加密且口令未知、token 绑定设备/Keystore 时，本方法不成立或影响有限。

## 检测与防御

- 检测：Manifest 中 `allowBackup=true` 且未排除敏感目录；应用数据目录含明文 token/会话；`adb backup`/`adb restore` 异常调用。
- 防御：敏感应用设置 `android:allowBackup="false"`；必须备份时用 `fullBackupContent`/`dataExtractionRules` 排除 token、数据库、密钥；不要把长期 token 放在可备份存储。
- 加固：token 绑定设备/Keystore、短期有效、可远程吊销；敏感数据加密并分离密钥；恢复备份后强制重新认证/二次验证。
- 响应：发现备份泄露时吊销会话、轮换密钥、通知用户；检查是否有异常登录。
