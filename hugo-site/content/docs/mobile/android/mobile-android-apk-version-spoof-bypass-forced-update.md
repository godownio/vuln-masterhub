---
id: mobile-android-apk-version-spoof-bypass-forced-update
title: APK 改 versionName/versionCode 绕过强制更新：jadx 定位两处版本字段 + apktool 重打包 + keytool/jarsigner/zipalign 重签
type: scenario
domain: mobile
path: mobile/android
technique: apk-version-field-patch-forced-update-bypass
tags:
- android
- apk
- repack
- resign
- apktool
- jadx
- zipalign
- version-spoof
cve: []
severity: info
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:34:15+08:00'
  notes: 已对照原文核对：jadx 全局搜 7.4.2 定位 AndroidManifest 与 com.vqs.iphoneassess.BuildConfig（classes2.dex）两处、apktool d/b、keytool -genkey、jarsigner -sigalg SHA1withRSA、zipalign -v 4 顺序与正文一致；本次核对未读取图片，仅依据正文文字，故卡内『21 张截图中的具体文件路径/命令回显/弹窗消失现象』未核对；卡内补充的 versionCode 与 apktool.yml versionInfo 同步、签名校验边界的建议属正文未明说的合理外推，已由『变体与关联』标注为边界
url: /docs/mobile/android/mobile-android-apk-version-spoof-bypass-forced-update/
draft: false
kb_aliases:
- 绕过强制更新
- 改 APK 版本号
- versionName 重打包
- BuildConfig.VERSION_NAME 修改
- apktool 重打包重签
- 强制更新弹窗绕过
---

## 一句话结论

强制更新是客户端把自己本地的版本号与服务端下发的最新版本比较后弹窗拦停，所以只要把 APK 里**所有**承载版本号的位置（`AndroidManifest.xml` 的 `versionName`/`versionCode`，以及被编译进 dex 的 `BuildConfig.VERSION_NAME`/`VERSION_CODE`）统一改成服务端那个"最新版本"，重打包重签安装后，比较结果相等，更新弹窗与拦停逻辑就不再触发。

## 原理

- **版本比较发生在客户端**：应用启动或进入主页时请求服务端版本接口，拿到 `latest_version` 后与本地 `PackageInfo.versionName` 或自己的 `BuildConfig.VERSION_NAME` 比较，判定"过低"就弹不可取消的更新框并阻断后续界面。判据完全在本地，因此改本地值即可让条件不成立。
- **版本号有多个副本，必须一起改**：`AndroidManifest.xml` 里的 `versionName`/`versionCode` 决定 `PackageInfo`（`getPackageManager().getPackageInfo()` 读到的那份），而代码里直接引用 `BuildConfig.VERSION_NAME` 时读到的是**编译期常量**——它已被内联进 dex，改 Manifest 不会同步它。只改一处时常见现象是"设置页显示新版本但弹窗照旧"或反之。
- **为什么必须先反编译定位再动手**：`BuildConfig` 属于某个包（示例在 `com.vqs.iphoneassess` 下），会被编进某一个 `classesN.dex`，直接全局替换二进制里的字符串有风险（可能改到无关常量或长度不一致），先 jadx 全局搜版本串确认所有出现位置，再用 apktool 落到具体 smali/资源文件改，最稳。
- **为什么重打包必须重签**：apktool 解包-回包会改变 zip 内容，原签名失效，Android 拒绝安装；必须用新 keystore 重新签名。用 `jarsigner` 做 v1（JAR）签名即可在多数设备安装；`zipalign` 只是把未压缩数据对齐到 4 字节边界以优化运行时内存映射，不改变签名有效性（应在签名后对齐，或对齐后再签，顺序不对手机会报未对齐）。
- **为什么这算"绕过安全机制"而非单纯改版本**：强制更新常用于推送安全修复；绕过后可以继续停留在含已知漏洞的旧版本上使用（例如配合其它客户端侧漏洞、或继续复用已被修复的接口行为），因此该手法在评估"版本强制策略是否可被规避"时有意义。

## 触发条件

- 目标应用用**客户端比较 + 弹窗/拦停**的方式实施强制更新（非服务端直接拒绝旧版本 API 请求）。
- APK 未加固或加固可被正常反编译（本例 jadx 能直接看到 `BuildConfig`）；有壳时需先脱壳，或只改 Manifest + 资源（此时 `BuildConfig` 常量仍是旧值，可能不生效）。
- 应用未做签名校验/完整性校验（改签后不闪退）；若存在签名校验，需额外 patch 校验逻辑或改用运行时 Hook。
- 设备允许安装来自未知来源的、与原应用同包名但签名不同的 APK（需先卸载原应用；数据会丢失，必要时先备份）。

## 利用步骤

1. **定位版本串**：`jadx` 打开 APK，全局搜索当前版本号（示例 `7.4.2`），记录全部命中位置；本例两处：`AndroidManifest.xml` 的 `versionName`，以及 `com.vqs.iphoneassess.BuildConfig` 的 `VERSION_NAME`（该类被编译进 `classes2.dex`，对应 smali 路径需按包名推导）。
2. **反编译为可改工程**：`apktool d target.apk` 得到目录，里面含 `AndroidManifest.xml`、`apktool.yml`、`smali*/`。
3. **改 Manifest**：把 `versionName` 改为目标最新版本；`versionCode` 若被用于比较，一并改到不小于服务端要求的值（`apktool.yml` 里的 `versionInfo` 同步改，避免回包时被覆盖回原值）。
4. **改 BuildConfig smali**：在 `smali*/<包路径>/BuildConfig.smali` 中把 `VERSION_NAME`/`VERSION_CODE` 的常量改成相同值。
5. **回包**：`apktool b <目录>`，产物在 `dist/` 下。
6. **生成签名密钥**：`keytool -genkey -v -keystore new.jks -alias <alias> -keyalg RSA -keysize 2048 -validity 10000`。
7. **签名**：`jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore new.jks -storepass <pwd> -signedjar signed.apk unsigned.apk <alias>`。
8. **对齐**：`zipalign -v 4 signed.apk aligned.apk`。
9. **安装验证**：卸载原应用后安装 `aligned.apk`，打开确认更新弹窗不再出现，且"关于/设置"里的版本号已是新值。

## PoC

```bash
# 1) 反编译（先 jadx 全局搜版本串，确认所有出现位置）
jadx -d jadx_out target.apk
grep -rn "7\.4\.2" jadx_out | head

# 2) apktool 解包
java -jar apktool_2.9.0.jar d target.apk -o apk_out

# 3) 改两处版本：AndroidManifest.xml 的 android:versionName / android:versionCode
#    以及 smali 中 BuildConfig 的 VERSION_NAME / VERSION_CODE 常量（示例为 7.4.2 -> 7.5.1）

# 4) 回包
java -jar apktool_2.9.0.jar b apk_out -o dist/unsigned.apk

# 5) 生成新 keystore
keytool -genkey -v -keystore new.jks -alias demo -keyalg RSA -keysize 2048 -validity 10000

# 6) 重签
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
  -keystore new.jks -storepass <password> \
  -signedjar dist/signed.apk dist/unsigned.apk demo

# 7) 4 字节对齐
zipalign -v 4 dist/signed.apk dist/aligned.apk
```

```text
验证：卸载原应用 → 安装 aligned.apk → 启动应用不再出现强制更新弹窗，
     设置/关于页的版本号显示为 7.5.1（与 BuildConfig 常量一致）。
```

## 变体与关联

- **只改 Manifest 的退化做法**：若应用只读 `PackageInfo`（不读 `BuildConfig`），改 Manifest 足够；反之若只读常量，则必须改 smali。判断依据是 jadx 里版本比较代码引用的是哪个字段。
- **更省事的工具链**：MT 管理器（移动端一站式解包/编辑/签名，部分功能收费）、`apksigner`（替代 `jarsigner`，支持 v2/v3 签名，新目标更兼容）、`uber-apk-signer`（批量自动对齐+签名）。
- **签名校验的应对**：若改签后闪退，先定位签名校验（对比 `getPackageInfo(GET_SIGNATURES)` 的哈希、或 native 层校验），改用 Frida 在运行时 Hook 校验函数返回原签名，比重打包更省事（参见 `[[mobile-android-apk-debuggable-repack-jadx-attach]]` 的调试附加与 `[[mobile-android-packer-apkid-frida-dexdump-jadx]]` 的脱壳思路）。
- **关联（同类重打包手法）**：`[[mobile-android-apk-debuggable-repack-jadx-attach]]`（补 `android:debuggable` 后重签以附加调试）——同样走解包/改清单/回包/重签，但目标是开调试而非改版本；`[[mobile-android-unity-il2cpp-frida-gadget-infinite-revival]]`（放入 gadget 后重打包重签）。三者共享 apktool + keytool + jarsigner 的工具链。
- **边界**：服务端若把最低版本校验放在**接口层**（旧版本请求直接返回错误/401），改客户端无效；有 Split APK / App Bundle 分发时需处理多包；加固壳与完整性校验会让 apktool 回包后的应用直接退出；改签会导致与原应用数据不兼容（需卸载，登录态丢失）。

## 检测与防御

- 检测（防守/风控侧）：同一账号出现"版本号已是最新但 APK 签名指纹与官方发布不一致"的请求（客户端上报签名哈希、证书指纹或 Play Integrity 结果即可识别）；安装包哈希不在官方发布清单中；异常版本组合（声称新版但部分新接口调用缺失）。
- 防御：把强制更新判定放到服务端（旧版本请求受限接口时直接拒绝并下发更新指引），不要只依赖客户端弹窗；启用签名校验与完整性校验（SafetyNet/Play Integrity、服务端比对证书指纹）；对关键接口做协议版本校验而非只看自称的 `versionName`；对已废弃旧版本的接口真正下线。
