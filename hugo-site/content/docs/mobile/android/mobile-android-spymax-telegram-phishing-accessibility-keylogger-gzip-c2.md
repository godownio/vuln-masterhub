---
id: mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2
title: SpyMax Android RAT：仿冒 Telegram 投递 + 无障碍服务键盘记录 + gzip over TCP 7771 下发命令/APK
type: scenario
domain: mobile
path: mobile/android
technique: spymax-telegram-phishing-accessibility-keylogger-gzip-c2
tags:
- mobile
- android
- rat
- malware
- accessibility-service
- keylogger
- gzip
- c2
- telegram
- phishing
- mitre-attack
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V312
  verified_at: '2026-11-08T12:29:09+08:00'
  notes: 已对照原文 content.md 与12张图核对：01 telegroms[.]icu 仿 Telegram 下载页（Telegram FZ-LLC/4.2星/10亿+下载/click to download）、02 应用抽屉第二个黑色纸飞机 Telegram（包名 reputation.printer.garmin）、03 无障碍请求话术、04 writeFile 写 /Config/sys/apps/log/log-yyyy-MM-dd.txt 且 Base64+">\r\n" 追加、05 onLocationChanged 采经纬度/精度/速度并 requestLocationUpdates(gps)、06 GZIPInputStream 解压函数、07 initializeService 的 ClientHost=MTU0LjIxMy42NS4yOA==→154.213.65.28、ClientPort=Nzc3MQ==→7771、08 Wireshark 154.213.65.28:7771 会话、09 gzip magic 1f 8b 与 data length、10 CyberChef 输出 1154.213.65.28:7771:AppData:...、11 plugins.angel.plugins.apps/info 的 Load/update/info 命令结构、12 解压后系统命令 ping 与 APK（PK/CERT.RSA）；IOC 包名/MD5/URL/C2 均一致。原文正文写 log-yyyy-mm-dd.log 而图4代码为 .txt，卡片按图取 .txt 已在原理注明；图11/12 的正文图注与实际内容互换，卡片按实际内容引用。未验证点：未安装/动态运行 APK、未复现 C2 上下行；原文无组件/样本版本，affected_versions 未设；frontmatter 无 sources/source_url。
url: /docs/mobile/android/mobile-android-spymax-telegram-phishing-accessibility-keylogger-gzip-c2/
draft: false
kb_aliases:
- SpyMax
- ready.apk
- telegroms.icu
- reputation.printer.garmin
- 154.213.65.28:7771
- Android 无障碍服务键盘记录
- gzip C2 流量
- 仿冒 Telegram APK
---

## 一句话结论

钓鱼站 `telegroms[.]icu` 仿冒 Telegram 下载页，诱导下载 `ready.apk`（包名 `reputation.printer.garmin`，图标仿 Telegram）；安装后反复要求开启无障碍服务，开启后作为键盘记录木马把 Base64 按键写入 `/sdcard/Config/sys/apps/log/log-yyyy-MM-dd.txt`，同时采集经纬度/精度/速度，数据 gzip 压缩后经 TCP 连 C2 `154.213.65.28:7771`（host/port 在代码中 Base64 混淆），C2 回包解压后是 `plugins.angel.plugins.*` 命令并可携带 APK（PK/`classes.dex`/`CERT.RSA`）下发更新。

## 原理

- **投递与伪装**：钓鱼页使用 Telegram 名称、Telegram FZ-LLC、4.2 星/10 亿+ 下载等文案和图标，按钮“click to download”指向 `https://telegroms[.]icu/assets/download/ready.apk`；安装后应用抽屉出现第二个仿 Telegram 图标（黑色纸飞机），包名却是与 Telegram 无关的 `reputation.printer.garmin`。
- **无障碍服务滥用**：APK 反复弹出“This App Request Accessibility Service: Click on Enable / Go to Downloaded Service / Enable [MY-NAME]”，直到用户开启。`AccessibilityService` 一旦授权，应用就能读取屏幕内容、模拟点击/滑动、监听输入事件，这是不 root 也能实现键盘记录与远程操作的关键；原文明确指出该 RAT 不需要 root。
- **键盘记录落盘**：`writeFile(String str)` 用 `Environment.getExternalStorageDirectory()` 拼 `/Config/sys/apps/log`，按日期创建 `log-yyyy-MM-dd.txt`；每条记录 `toBase64(str) + ">\r\n"` 追加写入（`BufferedWriter`/`FileWriter(..., true)`），并用 `synchronized (lockoflog)` 保证并发安全。外置存储目录便于攻击者/取证方直接读取。
- **位置采集**：`onLocationChanged(Location)` 把经度、纬度、精度、速度存入混淆字段，检查 `ACCESS_FINE_LOCATION`/`ACCESS_COARSE_LOCATION`，通过 `requestLocationUpdates("gps", ...)` 持续获取。
- **gzip 封装**：样本内有一个 gzip 流处理函数（`ByteArrayInputStream` + `GZIPInputStream` + `ByteArrayOutputStream` 循环 read/write，图 6），正文描述上行用 `gZIPOutputStream` 压缩；抓包中可见 `1f 8b` gzip magic 与 `32 38 00 32 38 00` 的数据长度字段。上下行都用 gzip 承载，压缩后数据在 TCP 上传输。
- **C2 地址混淆**：`initializeService` 中 `ClientHost = "MTU0LjIxMy42NS4yOA=="`（Base64 解码为 `154.213.65.28`）、`ClientPort = "Nzc3MQ=="`（解码为 `7771`）、`HideType = "C"`；`new Socket` 连 C2 后发送 gzip 数据。非标准端口 7771 + 加密/压缩通道是 MITRE 的 Encrypted Channel / NonStandard Port。
- **C2 命令与 APK 下发**：解压上行数据得到类似 `1154.213.65.28:7771:AppData:system_info:system_config:meta_data:154.213.65.28:10000010:[CR]:[V4]:...` 的字符串（含 IP、AppData、系统信息、配置、版本）；C2 响应解压后是 `plugins.angel.plugins.*` 命令结构，包含 `Load`、`update`、`info` 等方法名与参数；其中可嵌入完整 APK（`PK` 头、`AndroidManifest.xml`、`classes.dex`、`META-INF/CERT.RSA`），实现远程安装/更新。
- **MITRE ATT&CK**：防御规避（Obfuscated Files or Information、Virtualization/Sandbox Evasion、Application Discovery）、发现（Security Software Discovery、System Information Discovery）、收集（Email Collection、Data from Local System）、命令与控制（Encrypted Channel、NonStandard Port）。

## 触发条件

- 用户在移动浏览器打开仿冒 Telegram 页面并侧载 `ready.apk`（非 Google Play）。
- 用户按提示开启无障碍服务；Android 版本允许外部存储写入与网络访问。
- 设备可出网访问 C2 `154.213.65.28:7771`（TCP）；C2 在线时才能下发命令/APK。
- 分析侧需要 APK 样本、PCAP/流量包和 jadx 等工具。

## 利用步骤

（以下为分析与取证流程，不是执行恶意软件的操作步骤）

1. 获取样本：从钓鱼页/沙箱拿到 `ready.apk`，记录 MD5 `9C42A99693A2D68D7A19D7F090BD2977`、包名 `reputation.printer.garmin`、下载 URL。
2. jadx 反编译，定位 `AccessibilityService` 子类与权限声明（BIND_ACCESSIBILITY_SERVICE、INTERNET、READ/WRITE_EXTERNAL_STORAGE、ACCESS_FINE_LOCATION）；确认无障碍事件处理与键盘记录逻辑。
3. 搜索 `writeFile`、`getExternalStorageDirectory`、`Base64`、`GZIPInputStream`/`GZIPOutputStream`、`Socket`；记录日志路径 `/Config/sys/apps/log/log-*.txt` 与 C2 混淆字符串。
4. Base64 解码 `ClientHost`/`ClientPort` 得到 `154.213.65.28:7771`；在 PCAP 中过滤 `tcp.port == 7771`，观察 `1f 8b` gzip magic 与数据长度。
5. 用 CyberChef 的 From Hexdump → Gunzip（或 Python `gzip.decompress`）解压上下行；上行可读到 IP/AppData/system_info/system_config/meta_data/版本，下行可读到命令与 APK。
6. 从解压数据中按 `PK\x03\x04` 提取 APK，保存后用 jadx/aapt 分析其包名、权限与更新逻辑，判断是否为下一阶段载荷。
7. 按 IOC 排查设备/网络：包名、MD5、`telegroms[.]icu`、`154.213.65.28:7771`、`/Config/sys/apps/log/` 日志文件、异常无障碍授权。

## PoC

C2 地址解码：

```python
import base64
print(base64.b64decode("MTU0LjIxMy42NS4yOA==").decode())  # 154.213.65.28
print(base64.b64decode("Nzc3MQ==").decode())              # 7771
```

gzip 解压（把 PCAP 中 TCP payload 按 gzip 流提取后）：

```python
import gzip
raw = open("c2_payload.bin", "rb").read()
print(gzip.decompress(raw).decode("utf-8", errors="replace"))
# 期望看到类似 1154.213.65.28:7771:AppData:system_info:system_config:meta_data:...
```

从解压后的下行数据提取 APK：

```python
data = gzip.decompress(open("c2_down.bin", "rb").read())
i = data.find(b"PK\x03\x04")
if i >= 0:
    open("pushed.apk", "wb").write(data[i:])
```

样本关键代码（按原文图 4/7 整理）：

```java
public void writeFile(String str) {
    synchronized (lockoflog) {
        String date = new SimpleDateFormat("yyyy-MM-dd").format(new Date());
        File dir = new File(Environment.getExternalStorageDirectory(), "/Config/sys/apps/log");
        File f = new File(dir, "/log-" + date + ".txt");
        if (!dir.exists()) dir.mkdirs();
        if (!f.exists()) f.createNewFile();
        String line = Base64.encodeToString(str.getBytes(), Base64.DEFAULT) + ">\r\n";
        BufferedWriter w = new BufferedWriter(new FileWriter(f, true));
        w.append(line); w.newLine(); w.close();
    }
}

public class initializeService extends Service {
    public static String ClientHost = "MTU0LjIxMy42NS4yOA=="; // 154.213.65.28
    public static String ClientPort = "Nzc3MQ==";             // 7771
    public static String HideType = "C";
    // ...
}
```

## 变体与关联

- **同类无障碍 RAT**：[[mobile-android-spynote-fake-police-accessibility-credential-theft]] 是仿冒公安网站投递 SpyNote，靠无障碍窃取锁屏/金融/钱包凭据并阻止卸载；[[mobile-android-remote-assistance-apk-accessibility-mediaprojection-webrtc]] 是远程协助 APK 的无障碍 + MediaProjection + WebRTC 组合。本卡是 SpyMax 的仿 Telegram 投递 + 外置存储键盘记录 + gzip C2/APK 下发，家族与行为细节不同。
- **C2 协议变体**：其它 Android RAT 用 HTTP multipart、WebSocket、MQTT、Telegram Bot API 等；本卡是裸 TCP 7771 + gzip，且 host/port Base64 混淆。
- **分析工具**：jadx 静态、Frida 动态 Hook 无障碍/网络、PCAP + CyberChef；相关 APK 静态定位见 [[mobile-android-apk-static-entry-layout-resource-locate]]。
- **边界**：Android 11+ 分区存储会限制 `/sdcard/Config/...` 直接写入，样本可能申请 `MANAGE_EXTERNAL_STORAGE` 或改用应用私有目录；不同版本的无障碍授权 UI 文案不同；C2 可能已下线。

## 检测与防御

- **应用来源**：只从 Google Play/App Store 安装；浏览器出现“click to download APK”的 Telegram 页面基本可判定钓鱼；检查应用抽屉是否出现重复图标/包名不符（`reputation.printer.garmin` 伪装 Telegram）。
- **无障碍审计**：定期检查“设置 → 无障碍”中已启用的服务，撤销陌生应用；企业 MDM 禁用侧载与未知来源安装。
- **主机指标**：检查 `/sdcard/Config/sys/apps/log/log-*.txt`（Base64 + `>` 行）、异常 GPS 访问、应用申请 `BIND_ACCESSIBILITY_SERVICE` 与外部存储写权限。
- **网络检测**：监控 TCP 7771 等非标准端口出站、gzip magic `1f 8b` 的非 HTTP 流量、目标 `154.213.65.28`；DNS/URL 黑名单加入 `telegroms[.]icu`。
- **处置**：撤销无障碍、卸载应用、断网；若已授予敏感权限，重置相关账号并考虑恢复出厂；用信誉良好的移动安全产品全盘扫描。
- **合规**：仅在授权/隔离环境分析样本；不要安装或运行 APK 于个人设备。
