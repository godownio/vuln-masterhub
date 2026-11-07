---
id: binary-pwn-sandbox-escape-fastgpt-inspect-fglobals-original-refs
title: FastGPT v4.14.8 沙箱逃逸：inspect 帧回溯窃取 worker 原始 open/import 引用
type: scenario
domain: binary
path: binary/pwn/sandbox-escape
technique: fastgpt-sandbox-inspect-frame-globals-original-refs
tags:
- fastgpt
- python
- pyjail
- sandbox-escape
- inspect
- frame
- f_globals
- docker
- lateral-movement
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: v4.14.8（完整逃逸）；main 分支（文件读写可用，socket 被 audit hook 拦截）
verification:
  verified_by: verifier-V68
  verified_at: '2026-11-05T12:11:11+08:00'
  notes: 已对照原文与6张内嵌截图核对：图02 docker inspect 确认 v4.14.7.2 为 node projects/sandbox/dist/main.js、v4.14.8 为 bun run src/index.ts；图04 docker ps 含 fg-sandbox/fg-redis/fg-attacker；图05 攻击容器经 http://fg-sandbox:3000/sandbox/python 读 /etc/passwd 成功；图06 redis 返回 +PONG；图07/08 fastgpt-sandbox-audit --http 复现。原文的 _DANGEROUS_STDLIB 无 inspect、_validate_user_code 只拦 __subclasses__、_restricted_open/_safe_import 及模块级 _original_open/_original_import、exec(code, exec_globals) 的受限命名空间、main 分支 audit hook 拦 socket.__new__ 但文件读写仍可等细节均一致。affected_versions 按原文保留 v4.14.8 完整逃逸、main 部分可用。未验证点：未在本机复跑 worker.py/镜像与横向移动；原文为靶机/测试环境；frontmatter 无 sources/source_url。
url: /docs/binary/pwn/sandbox-escape/binary-pwn-sandbox-escape-fastgpt-inspect-fglobals-original-refs/
draft: false
kb_aliases:
- FastGPT 沙箱逃逸
- FastGPT 代码运行节点逃逸
- inspect.currentframe f_back f_globals
- _original_open _original_import 窃取
- worker.py 纯 Python 防护绕过
---

## 一句话结论

FastGPT v4.14.8 的 Python 沙箱把 `inspect` 留在了模块黑名单之外，而 open/import 守卫依赖的原始引用 `_original_open`、`_original_import` 就放在 worker 模块的全局命名空间里；用户代码用 `inspect.currentframe().f_back.f_globals` 拿到该字典后，可直接调用原始 open/import，实现沙箱容器内任意文件读写、socket 连接，并向同一 Docker 网络内的 redis/mongo/minio/fastgpt 主服务横向移动。

## 原理

- 执行模型：worker.py 用 `exec(code, exec_globals)` 执行用户代码。`exec_globals` 是沙箱构造的受限命名空间，其中 `_safe_builtins` 过滤掉以下划线开头的 builtins 名字，并显式替换 `__import__`、`open` 为安全版本。
- 四层防护及各自的盲点：
  1. **模块黑名单**：`_DANGEROUS_STDLIB` 覆盖 `os`、`subprocess`、`socket`、`fcntl`、`ctypes`、`sys`、`builtins` 等，但没有 `inspect`，因此 `import inspect` 直接放行。
  2. **AST 静态检查**：`_validate_user_code` 只拦截 `__subclasses__` 的直接属性访问和 `getattr(obj, '__subclasses__')` 常量参数写法；帧属性 `f_back`、`f_globals` 是单下划线，不在拦截表中。
  3. **open 守卫**：`_restricted_open` 通过 `traceback.extract_stack()` 检查调用者文件名是否为 `<string>`/`<test>`/`<module>`，是则拒绝；但原始 `open` 以模块级变量 `_original_open` 保存，守卫放行时直接调用它。
  4. **import 守卫**：`_safe_import` 对白名单 stdlib 直接放行，对危险模块检查调用栈；原始 `__import__` 同样以模块级变量 `_original_import` 保存。builtins 代理只阻止 `builtins._original_import` 属性访问，不阻止通过字典取值。
- 关键一步：`inspect.currentframe()` 返回用户代码自己的帧，`f_back` 是调用 `exec` 的 worker 函数帧（如 `_run_task`），它的 `f_globals` 就是 worker 模块的完整全局字典，`_original_open`、`_original_import` 全在其中。
- 为什么成立：Python 没有真正的模块级私有变量，模块全局字典对任何能拿到该模块命名空间的对象都是公开的。沙箱把守卫函数当作边界，却把守卫依赖的原始引用放在边界之外；而 `exec_globals` 的保护范围不覆盖 worker 模块自身的全局。
- 根因：模块黑名单、AST 属性黑名单、藏引用都是枚举式防护。攻击者只需找到一个漏网模块（`inspect`）和一个漏网属性类别（单下划线帧属性），四层防护会一起失效。

## 触发条件

- 目标运行 FastGPT v4.14.8 沙箱（Bun + Hono + worker.py 进程池，纯 Python 防护，无 seccomp、无 chroot），或 main 分支（Python 层同样漏 `inspect`，但外层有 chroot + seccomp 兜底）。
- 攻击者能向沙箱提交 Python 代码，入口包括工作流「代码运行」节点、多租户 SaaS 场景下的普通租户，或被接管的 FastGPT 管理员账号。
- 沙箱 HTTP API `/sandbox/python` 默认无认证：未设置 `SANDBOX_TOKEN` 时任何能访问该端口的客户端都能直接 POST 代码。官方 compose 未把 sandbox 端口映射到宿主机，因此外部攻击者不能直接访问，需要先进入 `fastgpt` Docker 网络（同网容器、SSRF 到 `sandbox:3000`、或被攻破的主服务）。
- 官方 compose 默认把 sandbox 与 mongo、redis、minio、fastgpt 主服务放在同一个 `fastgpt` 网络，容器名可被 DNS 直接解析，逃逸后横向目标就在隔壁。

## 利用步骤

1. 通过代码运行节点或 `POST /sandbox/python` 提交用户 Python 代码。
2. `import inspect`，取 `inspect.currentframe().f_back.f_globals` 得到 worker 模块全局字典。
3. 用 `g['_original_open']` 读写容器内任意文件；用 `g['_original_import']('socket')` 或 `('os')` 导入被黑名单禁止的模块。
4. 横向：连接 `redis:6379` 做 PING/GET/SET，连接 `mongo:27017`、`fastgpt-minio:9000`、`fastgpt:3000`；读取沙箱环境变量；主服务容器里的 `MONGODB_URI`、`AES256_SECRET_KEY` 是进一步放大的目标。
5. 通过接口返回的 `codeReturn`、写文件落盘或外连回显确认结果。

## PoC

```python
import inspect

g = inspect.currentframe().f_back.f_globals
f = g['_original_open']('/etc/passwd')
data = f.read()
f.close()

imp = g['_original_import']
sock = imp('socket')          # 黑名单模块，经原始 __import__ 导入

def main(v):
    return data[:120]
```

写文件与环境变量变体：

```python
import inspect

g = inspect.currentframe().f_back.f_globals
w = g['_original_open']('/tmp/pwned.txt', 'w')
w.write('PWNED')
w.close()

os_mod = g['_original_import']('os')
env_keys = sorted(os_mod.environ.keys())[:10]
```

## 变体与关联

- **main 分支变体**：Python 层仍然漏 `inspect`，`f_globals` 仍能摸到 worker 全局；把 `_task_tmpdir` 篡改为 `/` 后 audit hook 的路径检查放行，再用窃取到的 `_original_os_functions` 读写文件，实测文件读写仍成功。但 `socket.__new__` 被 audit hook 直接拒绝，且外层 chroot + seccomp + uid 65537 把影响限制在容器内，因此 main 上不是完整逃逸。
- **取帧路径替换**：若后续版本封禁 `inspect`，可改用异常回溯 `__traceback__.tb_frame`、未 await 协程的 `cr_frame`、生成器 `gi_frame` 等路径取帧，再读 `f_globals`/`f_builtins`；见关联卡。
- **同一根因的 seccomp 版本**：CVE-2026-32128 是「黑名单 + 藏引用」思路在 seccomp 层的失败——`SYS_FCNTL` 在白名单里，write 只按 fd 号放行 stdout/stderr，用 `fcntl.dup2` 重映射 fd 1 即可写任意文件；见关联卡。
- **部署模板滞后**：v4.14.8 发布时官方部署模板中的 `fastgpt-sandbox` 镜像 tag 仍指向 v4.14.7.2（seccomp 旧版），按默认模板部署实际运行的是带 CVE-2026-32128 的旧沙箱；到 v4.14.9 才更新 tag。审计「官方已修复」不能只看代码 diff，还要看部署模板是否同步。
- 关联：[[binary-pwn-sandbox-escape-python-traceback-frame-escape]]、[[binary-pwn-sandbox-escape-python-coroutine-cr-frame]]、[[binary-pwn-sandbox-escape-python-generator-frame-builtins-recovery]]、[[binary-pwn-sandbox-escape-python-regex-ast-alias-concat]]、[[binary-pwn-sandbox-escape-seccomp-write-fd-fcntl-dup2]]。

## 检测与防御

- 检测：用户代码中出现 `inspect`、`currentframe`、`f_back`、`f_globals`、`_original_open`、`_original_import` 等组合；代码节点提交内容包含帧对象属性访问。
- 检测：确认沙箱镜像版本与部署模板 tag 是否一致；检查 `/sandbox/python` 是否设置 `SANDBOX_TOKEN`；监控沙箱容器向 `redis:6379`、`mongo:27017`、`minio:9000` 发起的异常连接。
- 防御：升级到 main 分支（chroot + seccomp 至少把逃逸限制在容器内，但 Python 层仍漏 `inspect`，不是根治）；把 sandbox 拆到独立 Docker 网络，只允许访问必要服务，不与 mongo/redis/minio/fastgpt 主服务同网；设置 `SANDBOX_TOKEN` 并限制来源。
- 防御：模块 import 与属性访问都改为白名单；原始引用用闭包捕获，不要放在模块全局；不要把 Python 层当安全边界，使用 gVisor、Firecracker、bubblewrap + seccomp、只读文件系统、非 root、无网络等系统级隔离。
