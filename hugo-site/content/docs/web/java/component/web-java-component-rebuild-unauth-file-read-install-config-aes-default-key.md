---
id: web-java-component-rebuild-unauth-file-read-install-config-aes-default-key
title: Rebuild 未授权受限文件读取 ~/.rebuild/.rebuild 安装配置：默认 AES 密钥 REBUILD2018 解密数据库口令
type: scenario
domain: web
path: web/java/component
technique: unauth-file-read-config-default-aes-key
tags:
- java
- rebuild
- unauthorized
- file-read
- aes
- default-key
- credential-leak
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V577
  verified_at: '2026-11-12T11:16:41+08:00'
  notes: 已对照原文与8张图核对：isIgnoreAuth含/filex/放行、FileDownloader#readRaw的url参数经checkFilePath仅拦../、_log/、_backups/（图01）、可读~/.rebuild/.rebuild泄露db.url与db.passwd=AES(...)（图02）、AES#getPassKey默认REBUILD2018（图03）、AES#main解出rebuild（图04/05）。修正：PoC密文示例Dk8l->Dk81，与截图一致。原文仅称rebuild历史版本，无精确受影响版本，affected_versions留空。dedup候选为异产品（MetaCRM/WebLogic/Nacos等），非同链；库内无其他Rebuild卡。证据链完整，verified。
url: /docs/web/java/component/web-java-component-rebuild-unauth-file-read-install-config-aes-default-key/
draft: false
kb_aliases:
- Rebuild 未授权文件读取
- rebuild read-raw
- .rebuild 配置文件读取
- REBUILD2018 默认密钥
- Rebuild 数据库口令泄露
---

## 一句话结论

Rebuild 的鉴权拦截器对 URI 中包含 `/filex/` 的请求直接放行，而 `FileDownloader#readRaw`（read-raw 接口）的 `url` 参数经 `checkFilePath` 只拦截 `../`、`_log/`、`_backups/`，未拦截安装文件 `~/.rebuild/.rebuild`；未授权读取该文件可拿到数据库地址与 AES 加密的 `db.passwd`，在开发者未配置 `rbpass` 时 `AES#getPassKey` 回落到默认密钥 `REBUILD2018`，用 `AES#main` 即可解出数据库明文口令。

## 原理

- **鉴权白名单过宽**：`RebuildWebInterceptor#preHandle` 在 `isIgnoreAuth` 中对 `/f/`、`/s/`、`/gw/`、`/setup/`、`/filex/access/`、`/filex/download/`、`/filex/img/` 等前缀直接放行；更宽泛的分支是 `if (requestUri.contains("/filex/")) return true;`，只要 URI 里出现 `/filex/` 就跳过登录校验。若接口实现中不调用 `getRequestUser` 等取当前用户的逻辑，就形成未授权访问。
- **路径检查不完整**：`FileDownloader#checkFilePath` 先 `urlDecode`、把 `\` 换成 `/`，然后只拒绝包含 `../`、以/包含 `_log/`、以/包含 `_backups/` 的路径；`~/.rebuild/.rebuild` 不在黑名单内，且通过 `RebuildConfiguration#getFileOfData` 解析后能指向安装配置文件。
- **安装文件含数据库凭据**：`InstallState#checkInstalled` 通过 `Application.devMode() || ~/.rebuild/.rebuild 存在` 判断已安装；该文件保存 `db.user`、`db.url`、`db.passwd` 等初始化信息。`db.passwd` 形如 `AES(<base64 密文>)`。
- **默认 AES 密钥**：`com.rebuild.utils.AES#getPassKey` 依次读取环境变量 `rbpass`、系统属性 `rbpass`，都为空时使用 `defaultStr: "REBUILD2018"`。未显式配置 rbpass 的历史部署因此可用公开默认密钥直接解密 `db.passwd`，得到数据库明文口令。
- **影响延伸**：数据库口令可用于直连 MySQL（若端口可达或经内网）、读取/篡改业务数据，或结合"任意文件删除删除 .rebuild 触发未安装 setup 流程"走向 JDBC attack（该后续链本文未完整演示）。

## 触发条件

- 目标是 Rebuild 历史版本，服务已完成安装（`~/.rebuild/.rebuild` 存在）。
- `FileDownloader#readRaw` 对应路由可访问，且 URI 满足 `/filex/` 未授权放行条件（controller 未额外校验登录）。
- 部署未设置 `rbpass` 环境变量/系统属性，使用默认 AES 密钥。
- 数据库端口/网络可达或能借其他手段使用泄露凭据。

## 利用步骤

1. 识别 Rebuild 应用（低代码平台特征、`/user/login`、`/filex/` 等路由）。
2. 访问 FileDownloader 的 read-raw 路由，传 `url` 指向安装文件，例如 `url=<数据目录>/.rebuild/.rebuild`（具体前缀按 `getFileOfData` 的解析根确定；也可尝试 `~/.rebuild/.rebuild` 等写法）。
3. 读取响应中的 `db.user`、`db.url`、`db.passwd`；确认 `db.passwd` 是否为 `AES(...)` 格式。
4. 用 Rebuild 自带 AES 工具类（`com.rebuild.utils.AES#main` 或同逻辑脚本）配合默认 key `REBUILD2018` 解密 `db.passwd`。
5. 用解出的账号口令连接数据库，读取业务数据或进一步利用；如数据库仅本机可达，可结合 SSRF/内网代理。

## PoC

```http
GET /filex/download/read-raw?url=.rebuild/.rebuild HTTP/1.1
Host: target
```

```text
# 响应示例（~/.rebuild/.rebuild）
db.user=rebuild
db.passwd=AES(Dk81WYyWfMgmUAo2P8B5jg\=\=)
db.url=jdbc:mysql://127.0.0.1:3306/rebuild30?...
```

```java
// 默认 key 为 REBUILD2018；直接调用 Rebuild 的 AES#main/decrypt
System.out.println(AES.decrypt("<db.passwd 括号内的密文>"));
```

- read-raw 的实际路由前缀由 `FileDownloader` 类级映射决定（本文只给出方法级 `read-raw`），请求时按目标实际路由拼接。
- 若目标显式配置了 rbpass，默认 key 解密会失败，需另寻密钥或放弃该链。

## 变体与关联

- **同白名单的其他入口**：`/f/`、`/s/`、`/gw/`、`/commons/announcements`、`/commons/url-safe`、`/rbmob/env` 等未授权前缀下的接口都值得逐个测试是否存在类似文件/信息泄露。
- **任意文件删除 → 重新安装 → JDBC attack**：若能删除 `~/.rebuild/.rebuild`，`checkInstalled()` 变为 false，拦截器放行 `/setup/` 安装流程，攻击者可尝试在 setup 中指定恶意 JDBC URL 触发反序列化/远程加载（本文仅提出思路，未演示完整利用，按半链看待）。
- **默认密钥类问题**：产品内置 AES 默认 key 导致配置文件加密形同明文；同类可搜索 `REBUILD2018` 等硬编码常量定位其他部署。
- **未授权 SQL 注入**：同版本 `/filex/del-make-share` 的 ID 参数存在另一条未授权注入链，见相关卡片。

## 检测与防御

- **配置 rbpass**：部署时通过环境变量/系统属性设置强随机 `rbpass`，不要依赖默认 `REBUILD2018`；轮换已泄露的数据库口令。
- **升级修复**：升级到修复版本；若无补丁，限制 `/filex/` 路由的外部访问，或在网关层对 read-raw 的 `url` 参数做严格白名单。
- **路径校验**：禁止读取 `~/.rebuild`、配置目录与密钥文件；使用规范化后的绝对路径做前缀校验，而不是简单字符串黑名单。
- **监控**：审计对 read-raw 的请求，尤其是 `url` 含 `.rebuild`、配置、密钥字样的访问；监控数据库异常登录与大批量查询。
