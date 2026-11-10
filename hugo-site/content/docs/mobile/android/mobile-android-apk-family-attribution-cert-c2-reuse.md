---
id: mobile-android-apk-family-attribution-cert-c2-reuse
title: 恶意 APK 同源家族溯源：硬编码 C2 路径复用 + 签名证书指纹比对（thumbprint/序列号/有效期/DN）+ 日志 TAG 聚类
type: scenario
domain: mobile
path: mobile/android
technique: apk-family-attribution-cert-c2-logtag-clustering
tags:
- android
- malware
- attribution
- certificate
- apk-signing
- c2-reuse
- threat-intelligence
- clustering
cve: []
severity: info
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V424
  verified_at: '2026-11-09T17:28:48+08:00'
  notes: 已对照原文全文与图1/3/9/10/11核对：以 C2 域名/API 路径（https://forwarding.live/api、/site/number?site=customer-support10、/sms-reader/add）关联出同族多款 APK（图9 四个图标）、最早样本证书 Valid From 2024-03-19 14:20:02（图10）、分析样本证书 2024-04-10 10:54:18（图1/3）、证书 serial=1/thumbprint 与 DN CN=der/ST=gga 等观察均与原文一致；TAG mywork 聚类、按证书时间排序推家族活动起点的方法成立。未验证点：原文仅展示少量同源样本与两枚证书，“不同指纹但 DN/序列号/有效期一致=同 builder”属方法论推断；PoC 为通用分析命令，未对样本实际执行；sample 未运行。dedup 候选（C2 API MD5 签名重放、云盘窃密、AhMyth 等）均不同链；dup-scan.json(11-08) 早于建卡(11-09) 无本卡 pair；无 sources/source_url、无文章 ID/原文 URL/长段摘录（保留 C2 路径作为 IOC），path mobile/android 合法；非组件类无受影响版本。颗粒度：单一 APK 同源溯源工作流（C2/证书/TAG 三线索交叉），各线索是同一分析流程的步骤而非独立攻击原子，不判 split。
url: /docs/mobile/android/mobile-android-apk-family-attribution-cert-c2-reuse/
draft: false
kb_aliases:
- APK 家族溯源
- 签名证书指纹聚类
- C2 复用关联样本
- mywork 家族
- APK 证书 thumbprint 比对
- 恶意应用同源分析
---

## 一句话结论

拿到一个 Android 恶意 APK 后，可用三类稳定线索做同源家族扩展：① 硬编码的 C2 域名与 API 路径（同一团伙常用同一套后台，如 `/api/site/number?site=<品牌>`、`/api/sms-reader/add`）；② APK 签名证书的 SHA-256/SHA-1 指纹（同一签名密钥几乎不可能被不同开发者共用，指纹相同即同一发布者，指纹不同但 DN/序列号/有效期完全一致则可能是同一 builder 批量生成）；③ 代码中的固定日志 TAG 与包名/站点标识命名模式（如日志 TAG `mywork`）。三者交叉即可把单样本扩展为家族时间线，并用最早证书的生成时间估计活动起点。

## 原理

- **C2 与 API 路径复用**：同一恶意软件运营方通常用一套后台服务托管多个品牌/包名的 APK，API 路径、参数名（`site`、`message`、`sender`）与返回 JSON 字段（`data`）保持一致。以 C2 域名/URL 路径为 pivot 做威胁情报检索（VirusTotal 关系图、urlscan、被动 DNS、沙箱报告），能发现同后台的兄弟样本；`site` 值可直接区分同一家族的多个投放变体（如 `customer-support10`）。
- **APK 签名证书**：APK 的 v1/v2/v3 签名都带开发者证书，证书里有 Subject/Issuer DN、序列号、有效期与公钥；`keytool -printcert -jarfile app.apk`、`apksigner verify --print-certs` 或 VirusTotal 的 Certificate 页可直接读取。SHA-256/SHA-1 证书指纹是强身份标识：同一指纹 = 同一签名密钥 = 几乎可确定同一开发者；不同指纹但 DN 为乱码（如 CN/O/OU=`der`、ST/L=`gga`）、序列号相同、有效期起止高度接近，则提示由同一自动化 builder 或同一攻击者批量生成证书。
- **注意误判**：`serial=1` 与约 25 年有效期本身是很多正常 Android 开发证书（含 Android Studio 默认 keystore）的常见特征，不能单独作为恶意判据；可靠的是“证书指纹相同/证书模板细节高度一致 + 恶意行为/基础设施重合”的组合。
- **时间线**：证书的 `Valid From` 通常接近构建/签名时间，可作为样本出现时间的下界；把同源样本按证书生成时间排序，最早一枚（本例 2024-03-19）可把家族活动起点前推到分析样本（2024-04-10）之前。
- **日志 TAG 与命名**：代码里固定 `Log.d("mywork", ...)` 一类 TAG、包名（`com.bank.customersupport`）、应用名（`Customer Support`）、图标风格与 `site` 前缀（`customer-support10`）都是低成本聚类特征；TAG 在去混淆后仍常保留，适合批量检索。
- **为什么有效**：签名密钥更换成本高且会破坏应用升级链，攻击者倾向复用；C2 后台与 API 约定复用成本低；日志 TAG 属于开发习惯，改动少。三类特征相互独立，交叉验证可显著降低误报。

## 触发条件

- 已获得至少一个可解析的恶意 APK（未严重加壳或可脱壳），能读取证书与代码常量。
- 具备威胁情报检索条件（VirusTotal、应用市场/第三方 APK 站、被动 DNS、沙箱报告、公开推文等）。
- C2 域名/路径仍在用或历史记录可查；证书信息未被重签/二次打包掩盖（重打包会换证书，但签名指纹仍可标记新变体）。

## 利用步骤

1. 提取样本基础信息：包名、应用名、版本、哈希（MD5/SHA-1/SHA-256）、图标、证书。
2. 读取证书：`keytool -printcert -jarfile sample.apk` 或 `apksigner verify --print-certs sample.apk`，记录 Subject/Issuer DN、序列号、有效期、证书 SHA-1/SHA-256 指纹。
3. 从反编译代码提取 C2：搜索 `http`、`API_URL`、`site`、`/api/`，记录域名、路径、参数与 JSON 字段。
4. 以 C2 域名/证书指纹/TAG 分别检索：VirusTotal 的关系/同文件、urlscan、被动 DNS、GitHub/论坛/安全厂商报告；收集同域名或同证书的 APK。
5. 对每个候选重复步骤 1-2，按证书指纹分组；指纹不同但证书模板（DN/序列号/有效期）一致时标记为“同 builder 疑似同源”。
6. 按证书 `Valid From` 排序构建家族时间线；用包名/应用名/图标/site 前缀描述投放变体。
7. 输出 IOC 表：C2 与 API、证书指纹集合、包名集合、哈希集合、TAG，供阻断与持续监控。

## PoC

无恶意代码 PoC；以下为分析命令（静态读取，不运行样本）：

```bash
# 证书信息（选其一）
keytool -printcert -jarfile sample.apk
apksigner verify --print-certs sample.apk

# 快速提取 hash/字符串线索
sha256sum sample.apk
jadx -d out sample.apk
grep -rniE "https?://|API_URL|/api/|site" out/sources | head -50
grep -rn "Log\.[diew](" out/sources | head -50
```

```text
# 关联记录的字段模板：
包名 / 应用名 / SHA-256
证书 Subject DN / Issuer DN / Serial / Valid From-To / SHA-256 指纹
C2 域名 / API 路径 / 参数与 JSON 字段
日志 TAG / site 标识 / 图标
```

## 变体与关联

- 变体：攻击者可对每个 APK 使用不同签名密钥，此时依赖 C2/API 路径、`site` 参数、日志 TAG、代码结构与图标风格聚类；也可用重打包检测（签名与官方不一致）作为副线索。
- 变体：C2 可换成 Telegram Bot、云函数、共享托管上的随机路径；API 路径复用往往比域名更稳定（域名被封后换域名不换代码）。
- 关联：[[mobile-android-sms-received-forward-c2-number-banking-trojan]]（本方法分析的对象，含 `forwarding.live` C2 与 `site=customer-support10`）；[[mobile-android-ahmyth-rat-static-command-map]]（开源 RAT 的结构化静态分析）；[[mobile-android-spyware-clouddisk-contact-sms-photo-exfil]]（权限组合聚类）。
- 边界：证书被重签、代码混淆/加壳抹掉 TAG、C2 已下线且无历史 DNS 记录时，聚类只能依赖哈希相似度与行为特征，准确性下降；证书 `serial=1`/25 年有效期等常见默认值不能单独作为恶意判据。

## 检测与防御

- 检测（防御方/情报侧）：应用商店与 EDR 对同签名证书批量上架、证书 DN 乱码、已知恶意证书指纹做黑名单；监控同一 C2/API 路径被多包名应用复用。
- 检测：安全厂商报告与 VT 关系图更新后，用证书指纹与 C2 路径回溯历史样本，评估家族活动时间与投放品牌。
- 防御：终端/企业 MDM 阻断已知恶意证书与包名；应用市场对签名证书与开发者身份做实名核验；对“同证书多品牌客服类应用”做人工复核。
- 响应：把证书指纹与 C2 加入 IOC 库，持续监控新样本；对已安装用户按包名/证书排查，提取短信转发号码与后台接口做运营商侧处置。
