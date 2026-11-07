---
id: web-generic-auth-milvus-9091-expr-weak-token-unauth
title: Milvus 9091 管理端口 /expr 弱默认 token：auth=by-dev 未授权执行表达式（CVE-2026-26190）
type: scenario
domain: web
path: web/generic/auth
technique: management-port-expr-weak-token
tags:
- milvus
- vector-database
- auth-bypass
- management-port
- expr
- debug-endpoint
- weak-token
- info-leak
cve:
- CVE-2026-26190
severity: high
confidence: high
affected_versions: < 2.5.27 / < 2.6.10
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V67
  verified_at: '2026-11-05T11:57:59+08:00'
  notes: 已对照原文全文与12张内联截图核对：9091 /healthz OK、/expr?code=1+1&auth=by-dev 返回 {'output':'2'}、upper 表达式返回 HELLO-42、auth=wrong 被拒、2.6.5 仍 HIT 而 2.6.10 返回 expr endpoint is disabled、类型断言/分号/reduce 逃逸失败、/management/stop standalone 不支持，均与原文一致。affected_versions 依原文 CVE 区间设置。未验证点：未实际执行 PoC；distributed 的 /api/v1 无认证仅原文源码分析、未动态验证，卡内已注明；frontmatter 无 sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-milvus-9091-expr-weak-token-unauth/
draft: false
kb_aliases:
- CVE-2026-26190
- Milvus 9091 未授权
- /expr 弱 token
- by-dev 表达式执行
- Milvus 管理端口暴露
---

## 一句话结论

Milvus 的 9091 管理端口默认对外映射，其中 `/expr` 调试端点用从 `etcd.rootPath` 派生的默认值 `by-dev` 作为认证 token；任何知道 Milvus 默认配置的人都能带 `auth=by-dev` 未授权执行 expr-lang 表达式，且同端口上的 `/log/level`、`/eventlog`、`/metrics` 等端点同样无认证，形成管理面暴露与信息泄露。

## 原理

- `internal/http/server.go` 在 9091 注册了 `/healthz`、`/log/level`、`/eventlog`、`/expr`、`/metrics`、`/management/stop` 等路由；这些路由不在 19530 的 gRPC 认证拦截器覆盖范围内。
- `/expr` 的 handler 直接从 query 取 `code` 与 `auth`，调用 `expr.Exec(code, auth)`；`expr.Init()` 把 `authKey` 设为 `paramtable.Get().EtcdCfg.RootPath.GetValue()`，而 `etcd.rootPath` 的默认值是 `by-dev`。
- 因此 `auth` 不是密钥而是公开默认配置：只要目标没改 `etcd.rootPath`，`auth=by-dev` 即可通过；错误或缺省 auth 会被拒绝。
- 通过后可在 expr-lang 引擎中执行算术、字符串函数等表达式（如 `1+1`、`upper("hello")+"-"+string(42)`），属于任意表达式求值。原文测试的类型断言、分号、reduce 等逃逸尝试均被沙箱拦截，未发现 RCE。
- 同端口其他端点：`/log/level` 可运行时改日志级别，`/eventlog`、`/metrics` 泄露内部指标与事件信息；`/management/stop` 在 standalone 模式返回“不支持”，因此不构成 DoS。
- 版本差异：2.6.5 修复了 sourceid 后门，但 `/expr` 仍可用；2.6.10 才增加 `common.security.exprEnabled` 开关并默认 false，`/expr` 默认禁用。原文还提到 distributed 模式下完整 REST API `/api/v1/*` 注册在管理端口且无认证，但该条仅源码分析、未动态验证。

## 触发条件

- Milvus 版本 < 2.5.27 / < 2.6.10；2.6.5 等中间版本仍在影响区间。
- 9091 管理端口可从攻击者网络访问（compose 默认映射、公网暴露或内网可达）。
- `etcd.rootPath` 仍为默认 `by-dev`（或攻击者已知实际值）。
- 2.6.10 上若管理员显式开启 `common.security.exprEnabled=true`，`/expr` 仍会暴露。

## 利用步骤

1. 访问 `http://target:9091/healthz`，返回 `OK` 说明管理端口开放。
2. 请求 `http://target:9091/expr?code=1%2B1&auth=by-dev`，返回 `{"output":"2"}` 即弱 token 生效。
3. 用字符串函数等表达式确认可执行任意 expr-lang 表达式；用错误 auth 或缺省 auth 做对照，应被拒绝。
4. 枚举同端口未认证端点：`/log/level`、`/eventlog`、`/metrics`，收集版本、连接数、节点状态等信息。
5. 尝试 `/management/stop`；standalone 模式返回不支持，记录为不成立的 DoS 面。
6. 若目标是 distributed 模式，进一步检查 9091 上的 `/api/v1/*` REST API 是否无认证（需实际环境验证）。

## PoC

```bash
# 健康检查与端口确认
curl -s http://target:9091/healthz

# 弱 token 执行表达式
curl -s 'http://target:9091/expr?code=1%2B1&auth=by-dev'
# {"output":"2"}

curl -s 'http://target:9091/expr?code=upper(%22hello%22)%2B%22-%22%2Bstring(40%2B2)&auth=by-dev'
# {"output":"HELLO-42"}

# 对照：错误 auth / 缺省 auth
curl -s 'http://target:9091/expr?code=1%2B1&auth=wrong'
# {"msg":"failed to execute expression, the expr auth is invalid"}

# 同端口未认证端点
curl -s -o /dev/null -w '%{http_code}\n' http://target:9091/log/level
curl -s -o /dev/null -w '%{http_code}\n' http://target:9091/eventlog
curl -s -o /dev/null -w '%{http_code}\n' http://target:9091/metrics
```

## 变体与关联

- 变体：2.6.5 上 sourceid 已修复但 `/expr` 仍 HIT，形成“修一半”的中间版本；只升级到 2.6.5 不能消除管理端口风险。
- 变体：2.6.10 的修复是默认关闭 `/expr`，若业务显式开启 `exprEnabled=true`，弱 token 问题可能重新暴露，需同时修改 `etcd.rootPath`。
- 变体：distributed 模式下 `/api/v1/*` 注册在管理端口且无认证，攻击面比 standalone 更大；原文仅源码确认，未动态验证。
- 关联：[[web-generic-auth-milvus-sourceid-header-backdoor-fake-identity]]（同一认证体系的 sourceid 后门）；[[web-generic-auth-milvus-rootcoord-53100-unauthenticated]]（内部端口无认证）。
- 边界：`/expr` 沙箱较硬，原文未打通 RCE；若后续表达式引擎出现逃逸，该端点会升级为 RCE。`/management/stop` 在 standalone 不成立。

## 检测与防御

- 检测：9091 管理端口不应出现在公网资产中；监控 `/expr` 请求，尤其是 `auth=by-dev`、`code=` 含函数调用或超长表达式的请求。
- 检测：扫描 `/healthz`、`/expr`、`/log/level`、`/eventlog`、`/metrics` 等管理路由的暴露情况；检查 `etcd.rootPath` 是否仍为默认值。
- 防御：升级到 2.6.10+，保持 `common.security.exprEnabled=false`；修改 `etcd.rootPath` 为非默认值，避免弱 token。
- 防御：9091 只绑定内网/管理网，不映射到公网；用防火墙或安全组限制来源；管理端口与业务端口分离。
- 加固：删除或禁用不需要的 debug 端点；对管理端口加独立认证与审计；把管理面暴露检查纳入上线基线。
