---
id: web-generic-auth-ai-api-debug-env-disclosure
title: AI 推理服务 /debug 调试接口未鉴权：泄露 K8s API 地址、内网网关与数据库连接串
type: scenario
domain: web
path: web/generic/auth
technique: ai-inference-debug-env-disclosure
tags:
- ai
- ai-infrastructure
- ollama
- debug-endpoint
- information-disclosure
- missing-auth
- kubernetes
- mongodb
- redis
- cors
cve: []
severity: medium
confidence: low
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:23+08:00'
  notes: 已对照原文与图02核对：/debug返回environment中的OLLAMA_HOST/ORIGINS、INTERNAL_API_URL、KUBERNETES_SERVICE_HOST/PORT、MONGO_CONN_STR、REDIS_URL、hostname/internal_ip均一致；卡片已注明原文为模拟服务自定义端点、非Ollama通用能力，confidence=low。未验证点：PoC未本机复跑；frontmatter无sources/source_url。
url: /docs/web/generic/auth/web-generic-auth-ai-api-debug-env-disclosure/
draft: false
kb_aliases:
- AI API 调试接口泄露
- /debug 环境变量泄露
- AI 推理服务配置泄露
- Ollama 调试端点
---

## 一句话结论

生产环境遗留的 `/debug`（或类似管理/调试路由）未鉴权时，会直接返回进程环境变量，泄露 K8s API 地址、内部网关、MongoDB/Redis 连接串、主机名与 CORS 配置，为后续 SSRF、横向移动和凭据攻击提供完整目标清单。

## 原理

- 调试路由通常直接序列化 `os.environ` 或进程配置，本意是本地排障；部署到生产时没有按环境关闭。
- 管理/调试路由常与业务 API 共用同一鉴权策略，甚至完全没挂认证中间件；业务 API 若允许匿名推理，调试路由也会一起开放。
- 环境变量中常见 `KUBERNETES_SERVICE_HOST`、`KUBERNETES_SERVICE_PORT`、`INTERNAL_API_URL`、`MONGO_CONN_STR`、`REDIS_URL`，直接暴露内网拓扑与数据库入口。
- 若 `OLLAMA_ORIGINS=*` 或 CORS 返回 `*`，任意网站可在浏览器内跨域调用该 AI API（在浏览器可达该服务的前提下），为 CSRF/前端组合攻击提供条件。
- 该场景原文为模拟服务的自定义 `/debug` 端点，并非所有 Ollama 版本都默认提供；需要按实际框架与部署清单核实。

## 触发条件

- 目标 AI 推理服务存在 `/debug`、`/config`、`/env`、`/api/debug` 等调试路由，且可从攻击者网络访问。
- 路由无认证，或认证可被绕过/默认口令进入。
- 返回体包含 `environment`、`env`、`config` 等字段，或错误页/启动日志泄露同类信息。
- 攻击者需要先能访问 AI API 本身；若 API 仅内网可达，则需先通过 SSRF、代理或社工进入。

## 利用步骤

1. 直接请求 `/debug`，观察是否返回 JSON 环境变量；同时尝试 `/v1/models`、`/api/ps`、`/metrics`、`/health`、`/openapi.json` 做交叉确认。
2. 提取 `KUBERNETES_SERVICE_HOST`/`PORT`、`INTERNAL_API_URL`、`MONGO_CONN_STR`、`REDIS_URL`、`hostname`、`internal_ip`。
3. 用 `hostname` 的内网域名后缀做 DNS/子域枚举；用内部网关地址寻找 Dashboard、GitLab、K8s 等管理面。
4. 检查响应头 `Access-Control-Allow-Origin`；若为 `*`，评估浏览器侧跨域调用与 CSRF 组合。
5. 将泄露地址交给 SSRF/端口扫描/数据库客户端继续利用；数据库连接串若含口令可直接尝试登录。
6. 模型名、模型路径、量化格式等 `/v1/models`、`/api/ps` 信息可用于判断技术栈、版本与后续攻击面。

## PoC

```bash
# 读取调试接口
curl -s http://target-ai-api:11435/debug

# 提取关键字段
curl -s http://target-ai-api:11435/debug | jq '.environment'

# 检查 CORS
curl -sI http://target-ai-api:11435/ | grep -i access-control
```

无真实组件版本 PoC：原文为模拟服务，真实目标需先确认调试路由是否存在。

## 变体与关联

- 模型列表泄露：`/v1/models` 返回模型名、大小、量化等级；模型命名可能包含项目代号、环境名、内网域名。
- 进程列表泄露：`/api/ps`、`/v1/ps` 返回模型存储路径、显存占用、运行参数。
- 启动日志泄露：容器日志可能打印 `OLLAMA_HOST`、`OLLAMA_ORIGINS`、`OLLAMA_MODELS`、`OLLAMA_REMOTES`。
- 错误页泄露：未捕获异常返回堆栈与环境变量片段。
- 关联：Ollama 未授权 API、CORS 通配符、SSRF、K8s ServiceAccount 枚举、数据库弱口令。

## 检测与防御

- 生产环境关闭所有调试/管理路由，或在反向代理层直接 404；调试功能只绑定 localhost 并单独鉴权。
- 管理面与业务面使用不同端口、不同认证策略；管理面加 IP 白名单与强认证。
- 环境变量最小化：不要把数据库连接串、云密钥、K8s Token 放进普通环境变量；使用 Secret 挂载并限制进程可见性。
- CORS 改为明确信任域名列表，禁止 `*` 与凭据组合。
- 访问日志告警：对 `/debug`、`/config`、`/env`、`/api/ps` 的访问单独记录并告警；把 404/403 与 200 的探测行为纳入监控。
- 上线前基线扫描：检查调试路由、模型列表、进程列表、CORS 与未授权管理接口。

## 可信度与边界

- 原文的 `/debug` 是模拟服务自定义端点，不是 Ollama 官方 API 的通用能力；真实环境需按框架版本核实。
- 泄露的环境变量内容与内网地址均来自模拟环境，不能视为真实目标默认配置。
- 本卡作为“AI 推理服务调试接口信息泄露”的审计模式参考，confidence: low。
