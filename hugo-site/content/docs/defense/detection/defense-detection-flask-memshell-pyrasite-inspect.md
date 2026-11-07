---
id: defense-detection-flask-memshell-pyrasite-inspect
title: Flask 内存马查杀：pyrasite 注入进程遍历 app 注册表并 dis 反汇编
type: scenario
domain: defense
path: defense/detection
technique: flask-memshell-pyrasite-inspection
tags:
- python
- flask
- memshell
- pyrasite
- incident-response
- detection
- dis
- ssti
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:33:24+08:00'
  notes: 已对照原文核对：pyrasite-shell注入、遍历view_functions/before_request_funcs/after_request_funcs/error_handler_spec、dis.dis反汇编与_get_exc_class_and_code(404)步骤均对应原文'查杀'章节；卡内补充的globals()定位Flask实例写法合理。未验证点：原文无实测输出，我未本机执行；pyrasite依赖gdb/ptrace与Python版本兼容；frontmatter无sources/source_url。
url: /docs/defense/detection/defense-detection-flask-memshell-pyrasite-inspect/
draft: false
kb_aliases:
- Flask 内存马查杀
- pyrasite 注入 Flask
- view_functions 排查
- error_handler_spec 排查
- Flask 后门检测
- Python 内存马应急
---

## 一句话结论

Flask 内存马通常表现为运行期被写入 `app.view_functions`、`app.before_request_funcs`、`app.after_request_funcs`、`app.error_handler_spec` 等注册表的匿名函数或 `exec` 生成函数；应急时可用 pyrasite 把交互式 Python 注入到运行中的 Flask 进程，遍历这些注册表并用 `dis.dis` 反汇编，定位并清除命令执行/动态代码逻辑。

## 原理

- Flask 的路由、请求钩子、错误处理器都保存在应用对象的普通 dict/list 中（`url_map`/`view_functions`/`before_request_funcs`/`after_request_funcs`/`error_handler_spec`）。内存马不落地文件，只修改这些运行期对象，因此文件扫描和重启前的磁盘取证都难以发现。
- pyrasite 通过 gdb attach 到 CPython 进程，在目标进程内执行 Python 代码（`pyrasite-shell <pid>` 提供交互式 shell）。进入目标进程后，`globals()`/`locals()` 可直接找到 `app`/`application` 对象，进而读取上述注册表。
- `app.view_functions` 是 `endpoint -> view function` 的映射；正常视图通常有明确模块与源码文件，恶意注入常表现为 lambda、`<lambda>`、`exec` 生成函数、`__module__` 为空或 `co_filename` 为 `<string>`。
- `app.error_handler_spec` 是嵌套字典：`[blueprint][code][exc_class] -> handler`；对 404 可用 `app._get_exc_class_and_code(404)` 取出 `(exc_class, code)` 再索引。
- `dis.dis(func)` 输出函数的 Python 字节码，可直接看到 `os.popen`、`subprocess`、`exec`、`eval`、`__import__` 等调用；对 lambda 同样适用。
- 该方法的边界：需要 attach 权限（同用户/root、ptrace 未被禁用）；容器内需要 `SYS_PTRACE`；pyrasite 对 Python 版本/gdb 有兼容性要求，生产环境应先确认可用。

## 触发条件

- 已确认或怀疑 Flask 应用被植入内存马（例如出现异常路由、未知 `cmd` 参数响应、SSTI 告警）。
- 能登录目标主机并 attach 到 Flask 进程（同用户或 root），ptrace 可用。
- 目标为 CPython 运行的 Flask 应用；PyPy、多 worker 场景需分别处理每个进程。
- 已从 GitHub 安装可用的 pyrasite（文章指出 pypi 版本不可用）。

## 利用步骤

1. 定位进程：`ps aux | grep python` 或 `ps aux | grep app.py`，记录 PID。
2. 注入交互 shell：`pyrasite-shell <PID>`。
3. 在目标进程内定位应用对象：尝试 `app`、`application`，或遍历 `globals()` 查找 `Flask` 实例。
4. 枚举路由与视图函数，记录可疑 endpoint/函数：

```python
for route, func in app.view_functions.items():
    print(route, func, getattr(func, '__module__', None), getattr(getattr(func, '__code__', None), 'co_filename', None))
```

5. 枚举请求钩子与错误处理器：

```python
print(app.before_request_funcs)
print(app.after_request_funcs)
exc_class, code = app._get_exc_class_and_code(404)
print(app.error_handler_spec.get(None, {}).get(code, {}).get(exc_class))
```

6. 对可疑函数反汇编：

```python
import dis
dis.dis(app.view_functions['shell'])
dis.dis(malicious_handler)
```

7. 确认恶意逻辑后删除对应键/列表项，或直接重启进程；重启前保留内存快照/函数对象信息用于取证。

## PoC

```bash
ps aux | grep -E 'python|app.py'
pyrasite-shell 8
```

进程内：

```python
# 1) 找 app
import flask
app = next(v for v in globals().values() if isinstance(v, flask.Flask))

# 2) 列所有路由处理函数
for endpoint, func in app.view_functions.items():
    code = getattr(func, '__code__', None)
    print(endpoint, func, code.co_filename if code else None,
          getattr(func, '__module__', None))

# 3) 看错误处理器
exc_class, code_num = app._get_exc_class_and_code(404)
handler = app.error_handler_spec.get(None, {}).get(code_num, {}).get(exc_class)
print(handler)

# 4) 反汇编
import dis
dis.dis(app.view_functions['shell'])
```

输出中出现 `<lambda>`、`co_filename='<string>'`、字节码里的 `os.popen`/`subprocess.Popen`/`exec`，通常即为注入点。

## 变体与关联

- 变体：同时检查 `app.teardown_request_funcs`、`app.url_value_preprocessors`、`app.template_context_processors`、`app.jinja_env.globals`/`filters`，以及被 `setattr` 覆盖的 `handle_user_exception`/`process_response`。
- 变体：用 gdb 的 `py-bt`/`py-list`、`pyrasite` 的 dump 功能或进程内存取证工具替代交互 shell；多 worker 需逐个 PID 检查。
- 关联卡片：[[defense-detection-arthas-agent-memshell-detect-remove]]（Java 侧同类应急）、[[web-python-framework-flask-route-registration-memshell]]、[[web-python-framework-flask-hook-registry-memshell]]、[[web-python-framework-flask-method-override-component-memshell]]。
- 边界：pyrasite 注入本身会改变进程状态，生产环境操作前需评估；容器缺少 ptrace 权限时需在宿主机或特权容器内操作。

## 检测与防御

- 检测：对 Flask 进程定期做注册表基线快照（endpoint 列表、函数 `co_filename`/`__module__`、钩子数量），出现新增匿名函数或 `<string>` 源码即告警；监控对 Python 进程的 attach/ptrace 行为。
- 防御：限制生产主机 ptrace（`kernel.yama.ptrace_scope`、容器去掉 `SYS_PTRACE`），以非 root 运行应用；阻断 SSTI 与任意 `exec`/`eval`，这是内存马的前置条件。
- 处置：发现后重启进程、轮换密钥/会话，并审计所有可能被改写的注册点；仅删除单个路由或钩子不足以清除多入口植入。
