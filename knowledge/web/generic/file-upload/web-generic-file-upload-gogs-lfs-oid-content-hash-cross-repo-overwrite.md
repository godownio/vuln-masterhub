---
id: web-generic-file-upload-gogs-lfs-oid-content-hash-cross-repo-overwrite
title: Gogs ≤0.14.1 LFS 跨仓库 OID 覆盖：上传不校验 SHA-256 导致供应链投毒（CVE-2026-25921）
type: scenario
domain: web
path: web/generic/file-upload
technique: gogs-lfs-oid-hash-skip-cross-repo-overwrite
aliases:
- CVE-2026-25921
- Gogs LFS 漏洞
- LFS OID 覆盖
- 跨仓库 LFS 对象覆盖
- LFS 供应链攻击
- Git LFS 完整性绕过
tags:
- gogs
- git-lfs
- lfs
- oid
- sha256
- integrity
- supply-chain
- overwrite
- cve-2026-25921
cve:
- CVE-2026-25921
severity: critical
confidence: medium
status: verified
affected_versions: Gogs ≤ 0.14.1（修复版本 ≥ 0.14.2）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:07:38+08:00'
  notes: 已对照原文与两张源码截图核对：storagePath仅root+oid[0]+oid[1]+oid、Upload用os.Create覆盖+io.Copy且无SHA-256比对；CVE-2026-25921、CVSS 9.3、≤0.14.1/≥0.14.2与原文一致；PUT PoC原文仅返回200，未展示受害者拉取端到端结果；affected_versions按原文保留；PoC未复现
---

## 一句话结论

Gogs ≤0.14.1 的 Git LFS 本地存储只用 OID（内容 SHA-256）构造路径 `{root}/{oid[0]}/{oid[1]}/{oid}`，没有仓库维度；上传时又用 `os.Create()` 直接覆盖并 `io.Copy` 写入，**不重新计算、不校验上传内容是否等于 OID**。因此任意可推送 LFS 的注册用户在**自己的仓库**里声明受害者仓库已知的 OID 并上传恶意内容，就会覆盖全局存储中的同名对象；受害者后续拉取该 OID 时得到恶意内容，形成跨仓库供应链投毒（CVE-2026-25921，CVSS 9.3）。

## 原理

- **LFS 的基本假设**：OID 是文件内容的 SHA-256，作为不可变的内容寻址标识；正常实现必须保证“OID 唯一对应其内容”。存储路径按 OID 前缀分层只是分片手段，不应改变“内容与 OID 绑定”这一语义。
- **路径缺少仓库隔离**：`LocalStorage.storagePath(oid)` 返回 `filepath.Join(root, oid[0], oid[1], oid)`，路径完全由 OID 决定。不同仓库中相同的 OID 指向磁盘上同一个文件，跨仓库覆盖在存储层天然成立。
- **上传缺少完整性校验**：`Upload(oid, rc)` 先用 `os.Create(fpath)` 打开目标文件（存在则截断/覆盖），然后 `io.Copy(w, rc)` 把请求体写入，没有用 `sha256.New()` 对写入内容做哈希，也没有比较 `actualOid == oid`。服务端完全信任客户端声明的 OID。
- **攻击闭环**：攻击者从受害者仓库（公开仓库或已克隆的仓库）拿到 LFS 对象的 OID；在自己可控的仓库中调用 LFS 上传接口，URL 里填受害者的 OID、请求体放恶意内容；服务端按 OID 定位到同一全局文件并覆盖。受害者之后 clone/pull 该对象时，LFS 客户端按 OID 请求内容，服务端返回被覆盖的恶意字节。
- **为什么危害是供应链级**：LFS 常用于存放二进制依赖、模型、安装包、测试数据等；篡改后受害者难以通过常规代码 review 发现（内容不在 Git 对象库中，且 OID 看起来未变），可影响下游构建与分发。
- **修复要点**：0.14.2 改为临时文件 + `os.O_CREATE|os.O_EXCL` 防覆盖，边写边计算 SHA-256，写完后比较实际哈希与声明 OID，不匹配则删除临时文件并报错，最后 `os.Rename` 到最终路径。这样即使攻击者知道 OID，也无法用不同内容覆盖已有对象；已存在的对象按去重逻辑直接返回大小。

## 触发条件

- Gogs 版本 ≤0.14.1，使用本地 LFS 存储（`LocalStorage`）。
- 攻击者拥有一个可登录账号，能在自己的仓库推送 LFS 对象或直接调用 LFS 上传接口。
- 攻击者知道受害者仓库中某个 LFS 对象的 OID（公开仓库可直接查看；私有仓库需先获得读取权限或从构建日志/缓存等渠道获取）。
- 受害者后续会 clone/pull 该 OID（或 CI/构建流程会拉取 LFS 内容）。
- 存储后端没有额外的对象锁、版本控制或内容校验；CDN/缓存可能使旧内容短期继续存在，但不影响最终覆盖。

## 利用步骤

1. 在受害者仓库中定位 LFS 对象：查看 `.gitattributes`、`git lfs ls-files`，或直接读取仓库中的 LFS pointer 文件，得到目标 OID 与大小。
2. 用攻击者账号创建一个仓库，初始化 Git LFS；确认该实例的 LFS 上传端点（如 `/<owner>/<repo>.git/info/lfs/objects/basic/<oid>`）。
3. 直接向该端点发送 PUT 请求：URL 使用受害者的 OID，`Content-Type: application/octet-stream`，请求体为恶意内容，携带攻击者账号的 Basic/Bearer 认证。
4. 服务端返回 200，表示对象已按该 OID 写入/覆盖；可在攻击者仓库中触发一次 LFS 下载验证返回内容是否为恶意内容。
5. 等待或诱导受害者 clone/pull；受害者拉取该 OID 时得到恶意内容。若对象是依赖包/安装包/模型，可在下游构建或运行时触发。
6. 评估影响范围：该 OID 是否被多个仓库共享、是否被 CI 缓存、是否进入制品库；必要时清理缓存。

## PoC

```http
PUT /user2/public.git/info/lfs/objects/basic/5f8c5042d51400e9e2e9bed01353edacf72edc88340038145229cd494b5fe08a HTTP/1.1
Host: target:3000
Content-Type: application/octet-stream
Accept: application/vnd.git-lfs+json
Authorization: Basic <攻击者账号的 Basic 认证>

<恶意内容字节>
```

说明：`5f8c...e08a` 是原文件内容的 SHA-256（原文示例为 `Hello World` 的哈希），实际利用时替换为受害者仓库中目标 LFS 对象的 OID；请求体替换为恶意字节。服务端返回 `200` 表示接受并写入了该 OID；由于代码不校验请求体哈希，声明的 OID 与写入内容可以不一致。

## 变体与关联

- 变体（存储后端）：原文分析的是本地 `LocalStorage`；对象存储后端若同样按 OID 覆盖且不校验哈希，也可能受影响，需按实现确认。
- 变体（投递方式）：除直接 PUT `objects/basic/<oid>` 外，也可通过 LFS batch API 申请上传后上传；认证方式可为 Basic、Token 或会话。
- 变体（目标对象）：依赖包、模型权重、数据集、安装包、测试固件等；只要下游会按 OID 拉取并信任内容即可。
- 变体（影响放大）：若 CI 对 LFS 内容做缓存或制品分发，污染可能扩散到多个项目；若对象被自动执行（安装脚本、模型加载器），可进一步 RCE。
- 关联：[[web-generic-file-upload-unauth-object-storage-overwrite]]（同为“可预测 Key + 覆盖语义”导致完整性破坏；本卡是内容寻址 OID 且跨仓库、需要认证）。
- 关联：[[cloud-cicd-npm-postinstall-supply-chain-poisoning]]、[[cloud-cicd-pypi-optional-dependency-name-takeover]]（供应链投毒的不同环节）。
- 边界：目标已升级到 0.14.2+ 时，O_EXCL + 哈希校验会阻止覆盖；使用外部对象存储且开启版本控制/对象锁时，旧对象可恢复；受害者未重新拉取 LFS 内容时不会立即受影响。

## 检测与防御

- 修复：升级 Gogs 到 0.14.2 或更高版本；确认 LFS 上传逻辑包含实际 SHA-256 校验、`O_EXCL` 防覆盖、临时文件与原子重命名。
- 服务端校验：任何内容寻址存储都必须验证“内容哈希 == 声明 OID/Key”，失败即拒绝；禁止对已存在对象做覆盖写，重复上传按去重返回。
- 存储隔离：LFS 对象按仓库/租户隔离命名空间，或使用不可变存储/对象锁/版本控制；对关键对象做哈希基线。
- 供应链加固：下游对 LFS 拉取内容做哈希校验与签名验证；CI 缓存设置完整性校验；敏感依赖使用可验证来源与锁文件。
- 检测：同一 OID 在不同仓库/不同用户下被上传；LFS 上传请求的 `Content-Length`/实际哈希与 OID 不一致；同一对象短期内被覆盖写；受害者拉取后内容哈希与预期不符；Gogs 日志中出现对同一 `storagePath` 的重复 `os.Create` 写入。
- 运营：盘点公开仓库中的 LFS OID 暴露面；对历史对象做哈希审计；升级后回归 LFS 上传/去重行为。
