---
id: ai-security-gateway-security-apisix-kong-secret-at-rest-audit
title: AI 网关密钥加密声明的落盘核查：APISIX encrypt_fields 漏声明与 Kong OSS encrypted 空实现
type: scenario
domain: ai-security
path: ai-security/gateway-security
technique: ai-gateway-secret-at-rest-declaration-audit
tags:
- ai-security
- apisix
- kong
- ai-gateway
- credential-storage
- encryption
- etcd
- audit
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Apache APISIX 3.19.0；Kong Gateway OSS 3.9.3
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:26:33+08:00'
  notes: 已对照原文核对：APISIX 3.19.0 镜像内 encrypt_fields 计数（ai-request-rewrite=0；ai-proxy-multi 为 require 继承不误报）、同路由 etcd 落盘 ai-proxy 密文/rewrite 明文、Kong OSS 声明 4/读取 0 且 Admin API 回显明文，emb02/emb03/emb04 均与正文一致；属存储侧核查，最终风险取决于 etcd/Admin API/备份暴露面；未复跑
url: /docs/ai-security/gateway-security/ai-security-gateway-security-apisix-kong-secret-at-rest-audit/
draft: false
kb_aliases:
- APISIX encrypt_fields 漏声明
- Kong OSS encrypted 空实现
- AI 网关密钥明文落盘
- etcd 明文 provider 凭据
- 加密声明核查
---

## 一句话结论

插件 schema 里写了“加密”不等于凭据真的加密落盘：APISIX 3.19.0 的 ai-request-rewrite 未声明 `encrypt_fields`，同一条路由下它的 provider 凭据在 etcd 中是明文；Kong OSS 3.9.3 的 `encrypted = true` 只是企业版声明，OSS 全代码没有读取点，Admin API 直接返回明文。核查必须以存储层或运行时实际值为准，不能只读 schema 声明。

## 原理

### APISIX：加密循环只遍历插件自己声明的列表

- `apisix/plugin.lua:1207-1211` 的逻辑是：若 `schema.encrypt_fields` 存在且非空，才遍历该列表逐字段解密/加密；没有声明，这段循环根本不执行，值原样写入 etcd。
- 该机制还有两个前置条件（`apisix/plugin.lua:1075-1078`）：`apisix.data_encryption.enable_encrypt_fields` 为真，且 `core.config.type` 必须是 `etcd`。默认 `conf/config.yaml` 没有这一段，需要显式补上 `keyring`。
- `ai-request-rewrite` 的 schema 没有声明 `encrypt_fields`，但它的 `auth_schema` 与 ai-proxy 使用同一种结构（`header`/`query`）；运行时 `ai-request-rewrite.lua:131` 的 `auth = conf.auth` 把凭证转交给同一套 provider 层，`ai-providers/base.lua:208` 与 `:237` 把它当凭证头使用。两者走的是同一条凭证通路，唯一差别就是那行声明。
- 同族统计里的 `ai-proxy-multi.lua` 计数为 0，但它**不是**漏声明：它 `require("apisix.plugins.ai-proxy.schema")`，注册的是 `schema.ai_proxy_multi_schema`，加密声明随 require 的 schema 表一起继承。判断时要看“注册用的 schema 是否来自 require”，不能只看 `grep -c`。
- 关键观测点：Admin API 会把已声明的加密字段解密后再返回，所以两个插件从 Admin API 看都是明文；只有直接读 etcd 的落盘形态才能区分。

### Kong OSS：属性合法但无人读取

- `kong/llm/schemas/init.lua` 中 `header_value` 标了 `encrypted = true`，注释带 `[[ ee declaration ]]`（企业版声明）。
- OSS 的 `kong/db/schema/metaschema.lua:192` 把 `encrypted` 列为合法的布尔属性，因此 schema 校验会接受、不报错、不告警；同时 OSS 没有任何 rbac 实现，且全代码中 `.encrypted` 的读取处为 0。也就是说：声明合法、无人实现、静默忽略。
- 结果：dbless 模式下把 provider 密钥写在 `auth.header_value`，Admin API `/plugins` 原样返回明文。静默无效比直接报错更危险——报错至少会迫使使用者面对。

## 触发条件

- APISIX 3.19.0：部署开启了字段加密（`enable_encrypt_fields: true` + etcd 配置），并配置了 `ai-request-rewrite` 插件且带 `auth`；审计者/攻击者能读取 etcd 数据、etcd 备份或快照。
- Kong OSS 3.9.3：使用 ai-proxy 且凭据写在 `auth.header_value`；审计者/攻击者能访问 Admin API（默认仅 `127.0.0.1:8001`）或拿到声明式配置/备份。
- 该场景是“存储侧凭据保护核查”，不依赖远程未授权入口；风险大小取决于配置存储、Admin API 与备份的暴露面。

## 利用步骤

1. 盘点 AI 插件中承载 provider 凭据的字段（`auth.header`、`auth.query`、`header_value` 等），列出同族插件清单。
2. APISIX：在实际运行的镜像里统计 `encrypt_fields`；对计数为 0 的文件继续看它注册的 schema 是否从 `require` 继承，避免把 `ai-proxy-multi` 误判为漏声明。
3. APISIX：绕过 Admin API，直接读 etcd 的 `/apisix/routes`（或对应前缀），比较同一路由上不同插件凭据的落盘形态：已声明字段应为密文，未声明字段为明文。
4. Kong：在实际 OSS 镜像里统计 `encrypted = true` 的声明处与 `.encrypted` 的读取处数量；读取处为 0 即说明该属性在 OSS 无实现。
5. Kong：访问 Admin API `/plugins`，检查 `ai-proxy` 的 `config.auth.header_value` 是否为明文；若是，把 Admin API、声明式配置文件和 deck 仓库都按密钥材料管理。
6. 对发现的明文凭据立即轮换，并检查该存储（etcd、备份、Git 历史）的访问日志与访问范围。

## PoC

```bash
# APISIX：从实际发布镜像统计 encrypt_fields
docker run --rm --entrypoint /bin/sh apache/apisix:3.19.0-debian -c \
  'cd /usr/local/apisix/apisix/plugins; \
   for f in ai-proxy/schema.lua ai-proxy-multi.lua ai-rag.lua \
            ai-request-rewrite.lua ai-cache/schema.lua ai-rate-limiting.lua; do \
     printf "%-28s %s\n" $f $(grep -c encrypt_fields $f); done'

# APISIX：直接读 etcd 落盘形态（Admin API 会解密，不能作为证据）
docker exec etcd sh -c \
  "ETCDCTL_API=3 etcdctl get --prefix --print-value-only /apisix/routes" \
  | grep -v init_dir \
  | jq -r '"ai-proxy -> " + .plugins["ai-proxy"].auth.header.Authorization,
           "rewrite  -> " + .plugins["ai-request-rewrite"].auth.header.Authorization'
# 预期：ai-proxy 为密文串；ai-request-rewrite 为 Bearer 明文

# Kong OSS：声明处 vs 读取处
docker run --rm --entrypoint /bin/sh kong:3.9.3 -c \
  'echo -n "声明处: "; grep -c "encrypted = true" /usr/local/share/lua/5.1/kong/llm/schemas/init.lua; \
   echo -n "读取处: "; grep -rn "\.encrypted" /usr/local/share/lua/5.1/kong/ | wc -l'
# 预期：声明处 4，读取处 0

# Kong OSS：Admin API 返回明文
curl -s http://127.0.0.1:8001/plugins \
  | jq -c '.data[] | select(.name=="ai-proxy") | .config.auth'
```

## 变体与关联

- 变体：APISIX 的加密开关默认关闭。即使插件声明齐全，未显式开启 `enable_encrypt_fields` 时也仍是明文；文档里的 “Encrypted at rest” 容易被读成默认行为。
- 变体：Kong 企业版可能真实实现 `encrypted`，OSS 不实现；同一份 schema 在不同发行版行为不同，审计要以目标产物为准。
- 关联 [[ai-security-gateway-security-kong-ai-proxy-upstream-template-key-leak]]（密钥在运行时的去向）与 [[ai-security-gateway-security-higress-ai-proxy-internal-header-forgery]]（密钥/凭证在网关内部的归属），分别对应“存、去、归”三个环节。
- 边界：本卡证明的是“静态存储形态”，不直接给出远程利用；若 etcd 或 Admin API 本就对攻击者可达，则凭据泄露是直接后果。

## 检测与防御

- **APISIX 修复**：在 `ai-request-rewrite` 的 schema 中补 `encrypt_fields`，路径与运行时引用的 `auth` 字段一致；把“凡是 schema 含 provider 凭证字段的插件必须有 `encrypt_fields`”加进 CI，避免同族平行文件再漏一个。
- **APISIX 部署**：若依赖字段加密作为防护，必须把 `enable_encrypt_fields` 与 `keyring` 写入部署清单并显式开启；升级后如出现读取失败，按官方提示重存配置并核对 keyring。
- **Kong OSS**：既然 OSS 不实现该属性，只能缩小读取面——Admin API 保持只监听 `127.0.0.1`，声明式配置快照与 deck 的 Git 仓库按密钥管理；建议在 OSS 启动时对“声明了 encrypted 但本版本未实现”打告警，避免静默无效。
- **通用**：用存储层/运行时值验证加密声明；发现明文后轮换 provider 密钥，并审计 etcd、Admin API、备份与 CI 的访问记录。
