---
id: code-analysis-vuln-discovery-duplicate-extension-policy-divergence
title: 同产品两份后缀策略并存：从「弱的那一份被实际调用」找上传绕过入口
type: scenario
domain: code-analysis
path: code-analysis/vuln-discovery/pattern
technique: duplicate-extension-policy-divergence-audit
tags:
- code-audit
- file-upload
- blacklist
- whitelist
- configuration
- pattern
- spring-boot
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W5
  verified_at: '2026-11-08T14:31:06+08:00'
  notes: 已对照原文与图05/06/07/08/09核对：WebFileUploadController.upload(95-101行) → AbstractWebFileController.upload(121-129行 checkName) → checkName 227 行比对 filesExtensionBlacklist → getFilesExtensionExcludes(168-170行 split) 的调用链，以及 uploadsExtensionBlacklist/filesExtensionBlacklist 两份名单差集(html,htm,xhtml,xml,shtml,sh)均与原文一致；卡为通用审计模式，未设 affected_versions。未验证点：差集结论取自该产品源码截图，其他产品需自行核对；PoC 中的 Java 片段为按原文整理的形态示例。
url: /docs/code-analysis/vuln-discovery/pattern/code-analysis-vuln-discovery-duplicate-extension-policy-divergence/
draft: false
kb_aliases:
- 两份黑名单不一致
- 上传/文件管理各自一份后缀表
- 策略重复定义
- uploadExtensionBlacklist vs filesExtensionBlacklist
- 配置分叉审计
---

## 一句话结论

审计上传功能时，如果发现同一产品里存在两个语义相同的后缀策略变量（例如 `uploadsExtensionBlacklist` 与 `filesExtensionBlacklist`，或「上传白名单」与「文件管理黑名单」），不要假设它们等价：它们往往在不同代码路径上被分别读取，**覆盖率差的那一份决定了实际可上传范围**；把每个策略变量反查到它的调用点，找出「校验更弱但同样能写入同一目录」的那条路径，就是绕过入口。

## 原理

- 策略重复定义通常来自功能拆分：上传模块与文件管理模块由不同人/不同时期开发，各自新增了一个配置项；老的一份保留、新的一份叠加，代码里同时存在两套读取方法（`getUploadsExtensionExcludes()` / `getFilesExtensionExcludes()`），每个方法各自 `split` 一个独立字段。
- 两份名单覆盖范围常常不同：一份为了「防脚本执行」列了 `exe,com,bat,jsp,jspx,asp,aspx,php`；另一份为了「防静态页面注入」在此之上补了 `html,htm,xhtml,shtml`。前者弱、后者强，但两者都可能真实参与校验。
- 校验函数通常是同一个（例如 `checkName()` 里 `props.getFilesExtensionExcludes().contains(extension.toLowerCase())` 才拒绝），所以「用哪份名单」完全取决于调用链选了哪个属性方法；找到调用链比对比名单内容更重要。
- 由于是黑名单模型，弱的那份漏掉的类型默认放行；即使强的那份在别的路径上拦住了，攻击者只要走到弱路径且落点目录相同，就获得同等写权限。
- 规范化细节（`toLowerCase()`、取最后一个 `.` 之后、是否 `trim`）对两份名单同样生效，因此大小写绕过通常无效，真正的差量就是「名单条目的多少」。
- 审计价值：这类缺陷很难靠黑盒发现（黑盒只会看到「某些后缀被拒」），但一旦定位到分叉点，就能一次性解释「为什么某类文件能传上去」，并把结论推广到所有共用弱名单的接口。

## 触发条件

- 代码/配置中存在两个及以上语义重复的后缀策略（黑名单或白名单），且分别有独立的 getter/读取方法。
- 不同功能路径（上传、文件管理、模板、附件）分别调用其中一份做校验。
- 弱策略所在路径仍能把文件写入 Web 可访问目录（落点相同或等价）。
- 攻击者可通过该路径完成上传（有相应权限或该功能对低权限用户开放）。

## 利用步骤

1. 在配置类/常量类里 grep 后缀相关字段：`ExtensionBlacklist`、`ExtensionWhitelist`、`allowFiles`、`denyExt` 等，列出所有策略变量及其默认值。
2. 对每个变量找到它的 getter（如 `getFilesExtensionExcludes`、`getUploadsExtensionExcludes`），再 grep getter 的调用点，画出「策略变量 → 校验函数 → 接口」的映射表。
3. 对比各策略的条目集合（差集），特别关注：脚本后缀是否都齐、`html/htm/xhtml/shtml/svg` 是否只在其中一份里。
4. 找到「校验函数相同但传入策略较弱」的接口，确认它的落点目录与强策略接口是否同一可访问目录。
5. 用弱策略放行、强策略拒绝的后缀做上传实测（例如 `1.html`），验证是否成功落盘并可访问。
6. 把结论写成「每个接口实际生效的策略」，作为后续所有上传绕过的选点依据。

## PoC

```java
// 配置类里两份语义重复的后缀策略（示例形态）
private String uploadsExtensionBlacklist = "exe,com,bat,jsp,jspx,asp,aspx,php,html,htm,xhtml,xml,shtml,sh,htm";
private String filesExtensionBlacklist   = "exe,com,bat,jsp,jspx,asp,aspx,php";

public List<String> getUploadsExtensionExcludes() {
    return Arrays.asList(uploadsExtensionBlacklist.split(","));   // 强
}
public List<String> getFilesExtensionExcludes() {
    return Arrays.asList(filesExtensionBlacklist.split(","));     // 弱（实际被上传/文件管理路径使用）
}
```

```java
// 校验函数只负责「查名单」，查哪一份由调用方决定
if (props.getFilesExtensionExcludes().contains(FilenameUtils.getExtension(name).toLowerCase())) {
    throw new Http400Exception("Web file illegal extension: " + name);
}
```

```text
# 差集结论
强: exe,com,bat,jsp,jspx,asp,aspx,php,html,htm,xhtml,xml,shtml,sh
弱: exe,com,bat,jsp,jspx,asp,aspx,php
差: html,htm,xhtml,xml,shtml,sh  -> 走弱策略的接口可上传这些类型
```

```bash
# 审计检索：列出所有策略变量，再按 getter 名反查调用点
rg -n "ExtensionBlacklist|ExtensionWhitelist|allowFiles" src/
rg -n "getFilesExtensionExcludes|getUploadsExtensionExcludes" src/
```

## 变体与关联

- 变体：白名单版本的分叉（上传白名单含 `html`，文件管理白名单不含），结论相同：弱白名单决定可上传集合。
- 变体：同一策略被两处写入（一处初始化覆盖另一处），导致运行期实际生效值与源码字面量不一致；需在启动时打印/断点确认最终值。
- 变体：策略来自数据库/配置中心，页面上可编辑一份而另一份只读，同样形成分叉（配合「后台可改配置」类缺陷）。
- 关联：`[[web-generic-file-upload-upload-blacklist-miss-html-family-stored-xss]]` 是本模式在具体 CMS 上的落地危害（弱名单漏 html → 同源 XSS）；`[[code-analysis-vuln-discovery-storage-boundary-audit-pattern]]` 是更上层的「校验调用点覆盖」审计方法，本卡是其「策略重复定义」子模式。
- 边界：两份策略内容完全一致、所有路径都走强策略、或落点目录不可执行/不可访问时，分叉不产生实际绕过。

## 检测与防御

- 检测：代码里存在多个语义重复的后缀策略变量；审计记录中「配置项 → 调用点」映射出现一对多。
- 修复：后缀策略收敛为唯一定义（单例配置 + 单一 getter），所有校验点强制走同一份；把黑名单改为白名单。
- 加固：CI 中加入「策略变量唯一性」检查（同名语义常量只允许一处定义）；上线前对每个上传接口打印实际生效策略并纳入基线比对。
