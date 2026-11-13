---
id: mobile-android-axml-byte-fuzz-antidecompile
title: AXML 单字节 fuzz 反编译对抗：改 String Offsets 为越界下标，apktool/jadx 崩在 ArrayIndexOutOfBounds 而 APK 仍可安装运行
type: scenario
domain: mobile
path: mobile/android
technique: axml-byte-fuzz-antidecompile
tags:
- android
- apk
- axml
- androidmanifest
- anti-analysis
- fuzzing
- apktool
- jadx
- reverse-engineering
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V669
  verified_at: '2026-11-13T09:57:02+08:00'
  notes: 已对照原文与26张截图逐张核对：String Offsets scStringOffsets[17] 0x198(408)→0x5098(20632)、apktool 2.9.0 ArrayIndexOutOfBoundsException 20633@StringBlock.getUtf16、jadx 1.4.7 Index 20633/length 1148@CommonBinaryParser.skipStrLen16、重签名后 adb install Success 与 MainActivity 运行均一致；已修正 String Offsets 数组起点 0x5C→0x24（按截图 0x68 处 [17] 推算）。未复跑 fuzz 脚本；未显式版本区间，versions 保持省略
url: /docs/mobile/android/mobile-android-axml-byte-fuzz-antidecompile/
draft: false
kb_aliases:
- AndroidManifest fuzz
- AndroidManifest 反编译对抗
- apktool 对抗
- jadx 对抗
- String Offsets 越界
- AXML 单字节修改
- 反编译软件 DoS 对抗
---

## 一句话结论

在二进制 AndroidManifest.xml（AXML）上做单字节 fuzz，找到一个只影响反编译软件、不影响系统安装的改动：把 String Offsets 数组中的某个偏移从合法值改成远超字符串池大小的越界值（原文 `0x00000198`→`0x00005098`），apktool 2.9.0 与 jadx 1.4.7 解析 manifest 时都抛 `ArrayIndexOutOfBoundsException` 退出，而 APK 重新签名后 `adb install` 与运行正常——用作恶意 APK 的反编译对抗，同时保留可安装性。

## 原理

- **AXML 结构**：文件由 Header（magic 0x00080003、file size）、String Chunk（stringCount、stringsStart、stringOffsets[]、字符串数据）、ResourceId Chunk、XmlContent Chunk 组成；解析器大量依赖数组下标与偏移读取字符串。
- **越界偏移触发崩溃**：String Offsets 数组保存每个字符串相对字符串池的偏移。把其中一个值改成远超字符串池长度的值（如 20632/0x5098），反编译器在 `StringBlock.getUtf16(array, offset)` 中按该偏移读字节，再按长度计算读取范围，最终 `array[offset+1]` 越过数组边界，抛 `java.lang.ArrayIndexOutOfBoundsException: 20633`；apktool 报 `brut.androlib.res.decoder.StringBlock.getUtf16(StringBlock.java:276)`，jadx 报 `jadx.core.xmlgen.CommonBinaryParser.skipStrLen16(CommonBinaryParser.java:87)`，两者根因相同。
- **系统解析器不崩**：Android 的 AXML 解析路径对该越界值不敏感或只按需读取，APK 安装与运行正常；因此改动可只打击“分析工具”而不破坏“执行”。
- **已知旧手法**：早期把 magic 从 `03 00 08 00`（0x00080003）改成 `00 00 08 00`（0x00080000）可让 apktool 直接失败，但新版本已修复；改 `stringCount` 造成字符串池错位的思路也在 apktool 2.9.0 修复。因此需要 fuzz 找新的“单点”修改。
- **fuzz 空间与收敛**：示例 manifest 2308 字节，逐字节 0x00-0xFF 共 590,848 种；按“改为 0x00”或“改为与原文不同的某一值”收敛到 4616 种，脚本自动改字节→重打包→签名→跑 apktool 判定失败或成功→`adb install` 验证安装，跑一段时间即可筛出同时满足“反编译失败 + 可安装”的位置。
- **为什么要签名与安装验证**：部分改动会让系统也拒绝安装（`INSTALL_PARSE_FAILED_UNEXPECTED_EXCEPTION: Corrupt XML binary file`），只破坏反编译工具、保留安装才是可用的对抗手法。

## 触发条件

- 攻击者/样本作者能修改 APK 的二进制 AndroidManifest.xml 并重新打包、签名（需要私钥或重签名环境）。
- 目标分析者使用 apktool/jadx 等基于 AXML 解析的工具；工具版本未对越界偏移做完整性校验（原文 apktool 2.9.0、jadx 1.4.7 均受害）。
- 设备系统解析器接受该改动（原文 AOSP Android 11 验证安装运行正常）；不同 Android 版本/厂商 ROM 兼容性需实测。

## 利用步骤

1. 准备最小 demo APK，解压出二进制 `AndroidManifest.xml`，用 010Editor + `AndroidManifest.bt` 模板确认 Header/String Chunk 偏移（示例 stringCount=34，String Offsets 数组从 0x24 起；被改项 scStringOffsets[17] 位于 0x68）。
2. 建立基线：原版 APK 用 `apktool d` 可正常反编译；写脚本对 manifest 逐字节做单字节修改。
3. 每次修改后重打包为 zip、改后缀 .apk，`jarsigner` 重签名，运行 `apktool d -f` 判断是否异常退出（stdout/stderr 需实时读取，工具会等待 `Press any key to continue`）。
4. 对“apktool 失败”的候选再执行 `adb install`，筛出安装成功的样本；记录修改位置与原值/新值。
5. 复测跨工具：原文用同一改动测试 jadx 1.4.7，AndroidManifest.xml 解析失败；确认设备上应用可正常启动（截图 MainActivity Hello World）。
6. 将改动固化到样本；需要扩大对抗面时可继续做两位/三位组合修改。

## PoC

```text
# 原文验证通过的改动（String Offsets 内一项）
原值: 0x00000198
新值: 0x00005098   (20632)

# 效果
apktool 2.9.0:
  Exception in thread "main" java.lang.ArrayIndexOutOfBoundsException: 20633
    at brut.androlib.res.decoder.StringBlock.getUtf16(StringBlock.java:276)
jadx 1.4.7:
  Error decode manifest
  java.lang.ArrayIndexOutOfBoundsException: Index 20633 out of bounds for length 1148
    at jadx.core.xmlgen.CommonBinaryParser.skipStrLen16(CommonBinaryParser.java:87)

# 安装验证
jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore ./spring.keystore \
  -storepass 123456 -keypass 123456 -signedjar sign.apk ./app-debug.apk spring
adb install .\sign.apk
# Performing Streamed Install
# Success
```

```python
# fuzz 主循环示意（原文脚本结构简化）
for offset in range(len(manifest_bytes)):
    for val in (0x00, original[offset] ^ 0x01):  # 收敛后的候选值
        data = bytearray(original); data[offset] = val
        write_manifest_and_repack(data)          # zip -> apk
        sign_apk()                               # jarsigner
        if apktool_decode_failed() and adb_install_success():
            record(offset, original[offset], val)
```

说明：偏移/数值按原文截图（scStringOffsets[17]=20632、报错 20633/长度 1148）整理；fuzz 脚本为结构示意，未复跑；keystore 口令为原文示例。

## 变体与关联

- [[mobile-android-axml-manifest-hardening-repair]]：防守/分析侧——识别并修复同类被魔改的 AXML 字段（magic/stylesStart/stringCount），本卡是生产侧的 fuzz 找点方法，互为对手手法。
- [[mobile-android-assets-dex-magic-naga-repatch-cache-dump]]：DEX magic 改写的类似“改字节对抗工具”思路。
- [[mobile-android-apkid-yara-rule-packer-detection-mechanism]]：加固/对抗样本的检测特征。
- 变体：修改 String Offsets 多个元素、chunk size、ResourceId Chunk 或 XmlContent Chunk 中的长度字段；两位/三位组合扩大崩溃面；针对不同反编译工具（apktool 各版本、jadx、androguard）分别筛点；部分位置会让 Android 也拒绝安装，需安装验证。
- 边界：Android 版本/ROM 解析差异可能让“只坑工具”的改动变成“装不上”；apktool/jadx 后续版本可能增加边界校验使该点失效（如 magic、stringCount 旧点已被修复）。

## 检测与防御

- 检测（分析/查杀）：AXML 字段自洽性校验——stringOffsets 每项必须小于字符串池长度、chunk size 与 file size 一致、stringCount 与偏移表长度匹配；超出范围的值是典型加固特征。
- 检测：APK 可正常安装运行但 apktool/jadx 解析 manifest 抛 `ArrayIndexOutOfBoundsException`/`Invalid chunk type`，可直接作为“对抗样本”信号。
- 防御（分析侧）：使用带边界校验的解析器或先修复字段再反编译（见关联卡）；记录崩溃偏移快速定位被改字节；对样本做多工具交叉验证。
- 说明：该手法只提高静态分析成本，不构成运行期安全边界；动态分析、内存 dump 与运行时 Hook 不受影响。
