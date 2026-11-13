---
id: mobile-android-system-cacerts-openssl-subject-hash-push
title: Android 7+ 手工把 Burp CA 注入系统证书目录：openssl subject_hash_old 命名 + adb push cacerts
type: scenario
domain: mobile
path: mobile/android
technique: android-system-cacerts-manual-openssl-push
aliases:
- 系统证书手工导入
- openssl subject_hash_old
- cacerts 9a5ba575.0
- 夜神模拟器装证书
- Android 抓包证书
- adb push 系统证书
tags:
- android
- certificate
- ssl
- mitm
- burp
- openssl
- adb
- nox
- emulator
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V602
  verified_at: '2026-11-12T18:17:26+08:00'
  notes: 已对照原文与32张截图核对：img01 Burp CA DER导出、img02 openssl x509 转PEM+subject_hash_old输出9a5ba575并cp为9a5ba575.0、img03 adb push/mount remount/cp到/system/etc/security/cacerts/chmod 644/reboot、img04-05 WLAN代理192.168.1.101:8080与Burp All interfaces监听、img06 Android9 UA的HTTPS明文抓到，卡片步骤与PoC逐项一致（原文实测夜神Android9）。原文无组件/CVE版本，不设affected_versions。dedup：与android16 AlwaysTrustUserCerts卡（Android14+模块方案）及ssl-pinning-bypass-cert-frida卡（MoveCertificate迁移+pinning Hook）均非同一条链，属手工注入实现，保留；dup-scan.json不涉及。skipped的LSPosed/JustTrustMe安装链已在ssl-pinning卡覆盖，核对成立。
---

## 一句话结论

Android 7 起 APP 默认只信任系统 CA，用户安装的证书抓不到 App 流量；在已 root 的模拟器/设备上，把 Burp 导出的 DER 证书用 `openssl x509` 转 PEM、以 `subject_hash_old` 的 8 位哈希命名为 `<hash>.0`，`adb push` 到 `/system/etc/security/cacerts/`、`chmod 644` 后重启，即可让 App 把代理证书当作系统 CA 信任，配合代理设置直接抓 HTTPS 明文。

## 原理

- **信任模型**：Android 7.0 起 `NetworkSecurityConfig` 默认只信任系统 CA（`/system/etc/security/cacerts/`），用户证书（`/data/misc/user/0/cacerts-added/`）不再被普通 APP 信任，因此 Burp/Charles 的动态证书会导致 `certificate_unknown`。
- **目录命名规则**：系统证书目录按“文件名 = 证书 Subject 的旧式哈希 + `.0`”索引，TrustManager/OpenSSL 遍历目录时根据文件名匹配证书；`openssl x509 -subject_hash_old` 正是生成这个 8 位十六进制哈希（同格式的还有 `.1` 等后缀用于同 Subject 多证书）。
- **为什么必须系统目录**：把 CA 放进 `/system/etc/security/cacerts/` 后，系统在启动时把它当预置 CA 加载，APP 的标准 TrustManager 才会信任；放到用户证书区在 Android 7+ 无效。
- **分区只读**：`/system` 默认只读，需 `mount -o remount,rw /system` 重挂载才能写入；夜神等模拟器自带 root，`adb shell` 直接可写，无需 Magisk 模块。
- **版本边界**：该手工方法在 Android 7–13 的模拟器/root 设备上有效；Android 14+ 系统证书位于 APEX/只读分区且信任策略收紧，复制到 cacerts 可能不生效或被 AVB 阻止，需改用 AlwaysTrustUserCerts/MoveCertificate 等模块方案。
- 证书本身只是把“中间人”变成合法 CA：若目标 APP 还做了 SSL Pinning（OkHttp CertificatePinner/Conscrypt/native），信任系统 CA 仍会被 pinning 拒绝，需要额外的 Hook 绕过。

## 触发条件

- 模拟器或真机已 root（夜神自带 root 开关），能 `adb shell` 以 root 写 `/system`。
- Android 版本在 7–13 区间（手工写 cacerts 有效）。
- 代理工具（Burp/Charles）已生成 CA，设备与代理网络互通。
- 目标 APP 只用系统 TrustManager，未启用 SSL Pinning 或更强 RASP。

## 利用步骤

1. Burp：Proxy → Options → CA Certificate 导出 `Certificate in DER format`，保存为 `cacert.der`。
2. 转 PEM 并计算旧式主题哈希：
   ```bash
   openssl x509 -inform DER -in cacert.der -out cacert.pem
   openssl x509 -inform PEM -subject_hash_old -in cacert.pem
   # 输出 8 位哈希，如 9a5ba575
   cp cacert.pem 9a5ba575.0
   ```
3. 推送并写入系统证书目录（夜神 adb 路径 `<Nox>/bin/adb.exe`）：
   ```bash
   adb push 9a5ba575.0 /sdcard/
   adb shell
   mount -o remount,rw /system
   cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/
   chmod 644 /system/etc/security/cacerts/9a5ba575.0
   reboot
   ```
4. Burp 监听：Proxy → Options → Proxy listeners 绑定 `All interfaces`、端口 8080（不要只绑 loopback，否则模拟器连不上）。
5. 模拟器设置 WLAN 代理：主机 `192.168.x.x`、端口 8080（WLAN → 修改网络 → 高级 → 手动代理）。
6. 抓包验证：访问 HTTPS 站点或打开目标 APP，Burp 中出现明文请求即成功；若浏览器成功而 APP 失败，说明 APP 启用了 pinning，需转 Frida/Xposed 模块绕过复检。

## PoC

```bash
# 证书转换与命名
openssl x509 -inform DER -in cacert.der -out cacert.pem
HASH=$(openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1)
cp cacert.pem "$HASH.0"

# 写入系统目录（root adb）
adb push "$HASH.0" /sdcard/
adb shell "mount -o remount,rw /system && \
           cp /sdcard/$HASH.0 /system/etc/security/cacerts/ && \
           chmod 644 /system/etc/security/cacerts/$HASH.0 && reboot"
```

说明：`mount -o remount,rw /system` 在部分设备/Android 版本需改为 `mount -o rw,remount /`；原文实测环境为夜神模拟器 Android 9，证书名 `9a5ba575.0`。手工方法在 Android 14+ 不可用，见关联卡。

## 变体与关联

- 变体：用 Magisk 模块 MoveCertificate 把用户证书迁移/绑定到系统目录（无需重挂载 `/system`，Android 15 及以下可用）。
- 变体：Android 14+ 用 AlwaysTrustUserCerts（LSPosed/Xposed 模块）在应用进程内 Hook 信任链；Android 16 优先该方案。
- 变体：MT 管理器/RE 管理器在设备上直接复制证书到 `/etc/security/cacerts/`，效果等同 adb 手工写入。
- 关联：[[mobile-android-android16-certificate-trust-alwaystrustusercerts]]（Android 14/16 模块方案与版本边界）；[[mobile-android-ssl-pinning-bypass-cert-frida]]（系统证书就绪后的 pinning 绕过：TrustMe/objection/自定义 Frida）。
- 边界：APP 使用 pinning、mTLS、Play Integrity 或检测 root/系统证书变更时，仅注入系统 CA 不足以抓包。

## 检测与防御

- 检测：`/system/etc/security/cacerts/` 出现非厂商 CA、文件 mtime 异常；设备 root/可重挂载 `/system`；代理流量特征（Burp CA 指纹）。
- 防御：APP 使用证书/公钥 pinning、mTLS、Play Integrity 与 root 检测；敏感接口增加请求签名与设备绑定，降低中间人抓包价值。
- 运维侧：系统分区完整性校验（dm-verity/AVB）可阻止持久化写入；锁定开发者选项与 root。
