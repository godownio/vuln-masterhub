---
id: web-python-framework-jupyter-contents-shared-root-state-channel
title: 共享 Jupyter Server Contents API 无租户作用域：同实例同根目录下的跨隔离文件状态信道
type: scenario
domain: web
path: web/python/framework
technique: jupyter-contents-shared-state-channel
aliases:
- Jupyter Contents 跨租户文件信道
- root_dir + path 缺少 tenant_id
- 共享 Jupyter 任务投递
- Contents API 共享状态
- Jupyter 多租户隔离边界
tags:
- web
- python
- jupyter
- contents-api
- multi-tenant
- isolation
- covert-channel
- tornado
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V108
  verified_at: '2026-11-05T22:50:01+08:00'
  notes: 已对照原文与全部 51 张图核对：handlers.py 117-145/147-179、decorator.py 19-78、filemanager.py 464-560 行号与源码截图一致；同实例同 Token 同 root_dir 下 PUT/GET mbox_task 200、回执 PUT 200 与正文一致；第三张抓包仅证明回执写入的边界已如实标注；未复跑
---

## 一句话结论

Jupyter Server 的 Contents API 以 `path` 定位文件，`FileContentsManager` 再把它映射为 `root_dir + path`；当两个网络互不可达的客户端共享同一 Jupyter 实例、同一凭据和同一根目录时，双方对同一 API 路径的 `PUT`/`GET` 会落到同一文件，可在容器互不直连的情况下传递任务和回执。

## 原理

- `jupyter_server/services/contents/handlers.py` 的 `ContentsHandler.get`（L117-L145）把请求中的 `path` 交给 `contents_manager.get(...)`；同一文件的 `put`（L147-L179）也沿用该 `path`，按文件是否存在走保存或上传逻辑。
- `jupyter_server/auth/decorator.py` 的 `@authorized`（L19-L78）在访问 `contents` 资源前调用 `authorizer.is_authorized(self, user, action, resource)`；认证与资源授权都存在，但 URL 中的文件路径本身不会自动产生租户作用域，租户归属要由 authorizer、根目录或外层部署补上。
- `jupyter_server/services/contents/filemanager.py` 的 `FileContentsManager.get`（L464-L560）使用 `_get_os_path(path)`，结合配置的 `root_dir` 定位实际文件；`save`（L529-L560）同样把 API 路径写成文件。因此同一实例、同一身份、同一 `root_dir` 下，相同 API 路径就是同一份文件状态。
- 结果是：容器网络隔离只阻止了容器互访，并没有阻止它们通过共同可访问的 Jupyter 服务交换状态；安全边界实际落在“实例 + 凭据 + 根目录 + authorizer”上，而不是网络拓扑。

## 触发条件

- 多个沙箱/租户共享同一个 Jupyter Server 实例，或共享同一个 `root_dir`。
- 双方使用同一凭据（同一 token），或认证后映射到同一用户；对 `contents` 资源的授权允许读写目标路径。
- 没有按租户拆分实例、根目录或 authorizer 的资源判定；外层代理也没有做租户隔离。
- 客户端之间可以没有直接网络路径，但都能访问该 Jupyter 服务。

## 利用步骤

1. 确认目标为共享 Jupyter 部署：多个执行环境访问同一地址，且 token/身份相同（这属于部署前提，不是 Jupyter 的认证绕过）。
2. 攻击侧向固定路径写入任务文件，例如 `mbox_task`，内容为 JSON。
3. 受害侧用同一实例和凭据 `GET` 同一路径，读取任务；若流程允许，再向 `mbox_result` 写入回执。
4. 双方按约定的路径名和轮询周期交换消息；同一路径在 `root_dir` 下对应同一文件，网络隔离不影响传递。

## PoC

任务写入（本地对照，Token 已省略）：

```http
PUT /api/contents/mbox_task?token=<lab-token> HTTP/1.1
Host: jupyter.internal
Content-Type: application/json

{"type":"file","format":"text","content":"{\"op\":\"canary\"}"}
```

受害侧读取同一路径：

```http
GET /api/contents/mbox_task?token=<lab-token> HTTP/1.1
Host: jupyter.internal
```

本地对照结果：

```text
PUT /api/contents/mbox_task   -> 200 OK
GET /api/contents/mbox_task   -> 200 OK，content 包含 {"op":"canary"}
PUT /api/contents/mbox_result -> 200 OK，请求体 {"ack":true}
```

这组结果证明同一路径上的任务可写、可读、回执可写；它依赖“同一实例、同一身份、同一根目录”的实验前提，不证明绕过了 Jupyter 授权。第三张抓包只记录回执写入，不能单独证明攻击侧已读取回执。

## 变体与关联

- 共享状态原语的其他实现：Artifactory 的 Item Properties 用 `repoKey + itemPath` 定位可写属性；MinIO/S3 用 `bucket + objectKey` 和 `?tagging` 读写对象标签；两者与 Jupyter 的 `root_dir + path` 同属“共同服务 + 稳定对象坐标 + 一侧写另一侧读”。
- 若部署为每租户独立实例或独立 `root_dir`，同一 API 路径会落到不同文件，信道不成立；若 authorizer 把租户/会话纳入资源判定，也能阻断。
- 文件格式变体：文本、Base64、notebook 文件；目录创建与隐藏文件受 `allow_hidden` 等配置影响，本文未逐一验证。
- 关联：AI 代码执行沙箱共享状态信道（`ai-security-agent-security-sandbox-shared-artifactory-property-channel`）、对象存储元数据信道（`cloud-object-storage-metadata-covert-channel-tagging-multipart`）、间接提示词注入。
- 注意：这不是 Jupyter 默认配置的跨租户漏洞；多用户环境下的隔离取决于实例、根目录、认证和 authorizer 的组合。

## 检测与防御

- 部署隔离：每个租户/沙箱使用独立 Jupyter 实例或独立 `root_dir`；不要跨租户共享 token 或用户身份。
- 授权：authorizer 的资源判定必须包含租户/会话维度，不能只检查“是否有 `contents` 资源权限”；外层代理按身份注入租户上下文。
- 凭据：一租户一 Token，定期轮换；禁止把平台内部 Token 暴露给沙箱运行时。
- 检测：不同来源容器对同一 `path` 的交替 `PUT`/`GET`；共享 token 的跨租户使用；固定路径上的任务/回执式文件；异常的文件创建与覆盖；Jupyter 访问日志与容器网络拓扑不一致的读写。
- 响应：拆分实例/根目录、轮换 Token、清理共享路径中的异常文件、审计跨租户文件访问。
- 局限：原文实验使用同一身份与同一根目录，只证明共享路径的通信能力；未验证真实多租户部署中的越权，也未给出具体受影响版本。
