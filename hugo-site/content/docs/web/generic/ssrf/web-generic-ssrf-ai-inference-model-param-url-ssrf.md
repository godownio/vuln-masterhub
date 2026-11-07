---
id: web-generic-ssrf-ai-inference-model-param-url-ssrf
title: AI 推理 API model 参数被当作 URL 拉取：回显式 SSRF 打内网 Dashboard、K8s API 与云元数据
type: scenario
domain: web
path: web/generic/ssrf
technique: ai-inference-model-param-ssrf
tags:
- ai
- ai-infrastructure
- ollama
- ssrf
- internal-network
- kubernetes
- cloud-metadata
- port-scan
- echo-ssrf
cve: []
severity: high
confidence: low
status: verified
created: '2026-11-05'
updated: '2026-11-06'
verification:
  verified_by: verifier-V113
  verified_at: '2026-11-06T02:00:21+08:00'
  notes: 已对照原文与图01-08核对：/v1/models、/v1/ps、/debug资产发现、model=http://10.0.0.100:8080/回显Dashboard、内网端口扫描、metadata IAM与K8s Secret读取示例均与原文一致；卡片已明确原文为模拟环境、K8s默认需认证、真实Ollama/vLLM/TGI通常不接受URL作model，confidence=low。未验证点：PoC未本机复跑；frontmatter无sources/source_url。
url: /docs/web/generic/ssrf/web-generic-ssrf-ai-inference-model-param-url-ssrf/
draft: false
kb_aliases:
- AI API model 参数 SSRF
- model 参数 URL 注入
- AI 推理服务 SSRF
- Ollama 兼容接口 model 注入
---

## 一句话结论

当 AI 推理服务的聊天/补全接口把 `model` 字段当作远程地址交给后端 HTTP 客户端拉取，并把抓取结果拼进回复时，未认证攻击者就得到一个“自带回显”的 SSRF：可读取内网 Dashboard、K8s API 与云元数据，并把响应直接带回客户端。

## 原理

- `model` 参数名义上是模型名，但部分 AI 兼容层或自定义加载器支持“按 URL 加载模型配置/权重”，后端会执行 `requests.get(model_url)` 或 `urllib` 打开该地址。
- 聊天响应会把抓取到的内容包装进 `choices[].message.content` 返回，攻击者不需要 DNSLog、反向代理或出网通道，内网 HTTP 响应直接回显。
- AI Pod 常部署在 GPU 节点，为拉取模型、连接推理队列与内部网关，出站策略往往比普通 Web Pod 更宽松；一旦 SSRF 成立，横向面更大。
- 该场景原文自述为模拟的 Ollama 兼容服务，并非 Ollama 官方 `/api/chat` 的默认行为；真实环境必须先确认后端是否把 `model` 当作 URL。K8s API 默认要求认证，原文中不带 Token 读取 `/api/v1/secrets` 的结果只可能来自模拟实现或显式开启匿名访问的集群，不能当作 K8s 默认配置。

## 触发条件

- AI 推理 API 可从攻击者网络访问，聊天/补全接口无需认证或攻击者已有可用凭据。
- `model` 参数被后端用于发起 HTTP(S) 请求（模型 URL 拉取、配置下载、兼容层代理等），且没有协议、域名或内网 IP 白名单。
- 响应会把目标内容回显给调用者，或至少能通过状态码、响应长度、耗时差异做盲探测。
- 后端所在 Pod 能路由到目标内网地址（业务网段、云元数据 `169.254.169.254`、K8s Service 网段等）。

## 利用步骤

1. 资产与实现确认：请求 `/v1/models`、`/api/tags`、`/api/ps` 获取模型名、量化格式、模型存储路径；请求 `/debug`（若存在）获取环境变量与内网地址；观察 `Access-Control-Allow-Origin` 是否为 `*`。
2. 建立正常基线：向 `/v1/chat/completions` 发送真实模型名，记录响应格式、耗时与 `content` 长度。
3. 注入 URL：把 `model` 改为 `http://127.0.0.1:8080/` 或 `http://10.0.0.100:8080/`，观察 `content` 是否出现目标页面的 HTML/JSON。
4. 内网测绘：复用同一接口批量替换 `host:port`，按响应长度、状态码、耗时区分开放端口；优先 80/443/8080/8443/27017/6379/11434/9090/3000。
5. 打内部管理面：访问内网 Dashboard 的 `/metadata`、`/k8s`、`/gitlab` 等链接；`/metadata/iam/security-credentials/<role>/` 可能返回云 IAM 临时凭证（AccessKey、SecretKey、Token），路径风格可辅助判断云厂商。
6. K8s 方向（环境相关）：访问 `http://10.96.0.1/api` 或 `kubernetes.default.svc` 确认 API Server 可达；若要读 Secret，需要 Pod 的 ServiceAccount Token/RBAC，或集群显式允许匿名访问，单纯 SSRF 不带凭据通常返回 401/403。
7. 凭证利用：Base64 解码 Secret 的 `data` 字段；用数据库连接串登录 MongoDB/Redis（若网络可达）；用云 IAM 临时凭证调用云 API（权限取决于角色策略）。

## PoC

```bash
# 正常基线
curl -s -X POST http://target-ai-api:11435/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2:7b","messages":[{"role":"user","content":"hi"}]}'

# SSRF 探测内网 Dashboard
curl -s -X POST http://target-ai-api:11435/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"http://10.0.0.100:8080/","messages":[{"role":"user","content":"ping"}]}'

# 端口探测（观察响应差异）
curl -s -X POST http://target-ai-api:11435/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"http://10.0.0.101:27017/","messages":[{"role":"user","content":"ping"}]}'
```

无真实组件版本 PoC：原文未给出可复现的真实组件版本与补丁区间，上述请求针对模拟服务；真实目标需先确认 `model` 是否被当作 URL。

## 变体与关联

- URL 片段混淆：`model=http://host/#qwen2:7b`，绕过简单的 `endswith` 模型名校验。
- `file://`：若后端 HTTP 库支持 file scheme，可读 `/etc/passwd` 或模型 blob；是否可行取决于实现。
- DNS 重绑定 / 302 跳转：域名先解析到攻击者 IP，再跳转到内网，绕过一次性解析校验。
- 十六进制/十进制 IP：`http://0x0a600001/` 表示 `10.96.0.1`，绕过字符串黑名单。
- 模型拉取接口 SSRF：部分推理框架的 `/api/pull` 接受远程模型源，入口不同但思路相同，需按具体框架版本核实。
- 关联：通用 SSRF、云元数据凭证窃取、K8s ServiceAccount/RBAC、AI 网关 SSRF。

## 检测与防御

- 应用层：`model` 参数只允许预定义模型名白名单（如 `^[A-Za-z0-9_.:-]+$`），禁止 URL 与文件路径；模型清单与请求参数分离。
- 协议层：模型加载器只允许 HTTPS 且目标域名在 registry 白名单；禁止 `127.0.0.0/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`；禁止跟随跳转，或对跳转后的目标重新校验；解析 DNS 后校验 IP，防重绑定。
- 网络层：对 AI Pod 下发 Egress NetworkPolicy，仅允许模型仓库与 DNS；阻断 K8s API、云元数据、数据库网段。
- 认证与最小权限：AI API 前置认证；Pod 使用专用 ServiceAccount 且不自动挂载 Token；RBAC 最小化。
- 日志与检测：记录 `model` 参数值；告警包含 URL 特征或内网 IP 的 `model`；监控 AI Pod 出站到 `169.254.169.254`、`10.96.0.1` 与非模型仓库域名；对比正常与异常请求的 `content` 长度/耗时。

## 可信度与边界

- 原文自述为模拟 AI API 环境，核心 SSRF 由自定义兼容层实现；真实 Ollama、vLLM、TGI 的聊天 `model` 字段通常是模型名，不能直接断言存在同款漏洞。
- K8s Secrets 未认证读取、云元数据 IAM 返回等结果依赖模拟服务或特定集群配置，使用前需核实。
- 本卡作为“AI 推理 API model 参数 SSRF”的审计模式与攻击链参考，confidence: low。
