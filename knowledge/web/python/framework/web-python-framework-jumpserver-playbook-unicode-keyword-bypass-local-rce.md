---
id: web-python-framework-jumpserver-playbook-unicode-keyword-bypass-local-rce
title: JumpServer 作业 Playbook 关键字黑名单绕过：\u 转义 delegate_to/ansible_connection 骗过文本检查，Ansible local 连接在 Celery 容器执行命令（CVE-2024-29201）
type: scenario
domain: web
path: web/python/framework
technique: jumpserver-playbook-unicode-escape-local-rce
aliases:
- CVE-2024-29201
- JumpServer playbook RCE
- delegate_to
- ansible_connection
- dangerous_keywords 绕过
- Ansible local connection RCE
- JumpServer 作业 RCE
tags:
- jumpserver
- ansible
- playbook
- unicode-escape
- keyword-bypass
- local-connection
- rce
- cve-2024-29201
cve:
- CVE-2024-29201
affected_versions: 3.10.6（文中复现版本；3.10.7 修复）
severity: high
confidence: high
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V475-fix
  verified_at: '2026-11-10T17:44:11+08:00'
  notes: V475 指出 dangerous_keywords 元组与 check_dangerous_keywords/search_keywords 实际位于 apps/ops/models/playbook.py（图21），job.py 的 JobExecution.check_danger_keywords 只是调用点。已更正原理段文件归属。绕过链/PoC/版本 3.10.6/3.10.7 核对不变。
---

## 一句话结论

已认证且能创建/编辑 Playbook 并执行作业的用户，把 `delegate_to: localhost` 与 `ansible_connection: local` 写成 YAML 双引号里的 `\u` 转义形式（`"\u0064elegate_to"`、`"ansible_\u0063onnection"`），就能绕过 JumpServer 基于原始文本的危险关键字黑名单；作业执行时 YAML 解析器还原出本地连接配置，Ansible 的 local 连接插件在 jms_celery 容器内直接执行任务命令，形成容器内 RCE（CVE-2024-29201）。

## 原理

- **输入链**：用户创建 Playbook → `PATCH /api/v1/ops/playbook/<pk>/file/`（`PlaybookFileBrowserAPIView.patch`）把 `content` 以 `key=main.yml` 写入 Playbook 工作目录 → 创建并执行作业 → `JobViewSet.run_job` 创建 `JobExecution` 并通过 `transaction.on_commit` 投递 `run_ops_job_execution` 到 Celery → 执行时 `before_start` 调 `check_dangerous_keywords()`，再由 `get_runner()` 返回 `PlaybookRunner`，最终 `ansible_runner.run(playbook=self.playbook, private_data_dir=..., envvars=...)` 运行该 Playbook。
- **黑名单的实现**：`apps/ops/models/playbook.py` 中定义类级 `dangerous_keywords = ('hosts:localhost','hosts:127.0.0.1','hosts:::1','delegate_to:localhost','delegate_to:127.0.0.1','delegate_to:::1','local_action','connection:local','ansible_connection')` 与 `check_dangerous_keywords/search_keywords`；`job.py` 的 `JobExecution.check_danger_keywords` 只是调用点。检查函数遍历工作目录下 `.yml/.yaml`，逐行删除空格、换行、制表、单双引号、垂直制表后做**子串匹配**，命中就抛 `Playbook contains dangerous keywords`。它检查的是原始文本，不做 YAML 语义解析。
- **绕过点**：YAML 双引号标量支持 `\uXXXX` 转义。把键写成 `"\u0064elegate_to"`（`\u0064`=`d`）与 `"ansible_\u0063onnection"`（`\u0063`=`c`），删除引号空格后得到的是 `\u0064elegate_to:localhost` 与 `ansible_\u0063onnection`，都不含黑名单要求的 `delegate_to:localhost` / `ansible_connection` 字面子串，检查通过。
- **为什么绕过之后就能执行**：Ansible 解析 YAML 时把 `\u0064elegate_to` 还原成 `delegate_to`、把 `ansible_\u0063onnection` 还原成 `ansible_connection`，任务被标记为在控制节点本地执行；local 连接插件不建立 SSH，而是直接在运行 Ansible 的进程（jms_celery 容器）里执行 `shell`/`command`。
- **为什么落在 Celery 容器**：jms_web 只反代 jms_core 的 API；作业由 core 侧投递到 Celery 执行，PlaybookRunner 在 Celery 容器内调用 ansible-runner。因此低权限入口（80/Web）写出文件，命令执行发生在 jms_celery。
- **补丁思路**：JumpServer 将 `PlaybookRunner` 拆出 `SuperPlaybookRunner` 子类，后者显式设置 `envs={"LOCAL_CONNECTION_ENABLED": "1"}` 供内部自动化流程使用；作业执行路径 `job.py` 仍用不设置的 `PlaybookRunner`。同时升级其分叉的 ansible-core，`local.py` 的 `Connection.__init__` 在未设置 `LOCAL_CONNECTION_ENABLED` 时直接抛 `AnsibleError("Local connection is disabled")`——从"黑名单过滤"改为"默认禁用本地连接、内部流程显式开启"。
- **未验证点**：分析中未完全还原 jms_core 到 jms_celery 的内部投递细节（MySQL/Redis 中未见序列化后的 yml），但复现中命令确实在 jms_celery 执行；卡以实际执行结果为准。

## 触发条件

- JumpServer 3.10.6 一类受影响版本（3.10.7 修复；其他版本以官方公告为准）。
- 已认证用户，且具备创建/编辑 Playbook、创建并执行作业的权限；执行时需绑定一个有效资产 ID（错误资产无法绑定）。
- 服务端使用未修复的分叉 ansible-core，作业执行路径未禁用 local connection。
- 攻击者能访问 `PATCH /api/v1/ops/playbook/<pk>/file/` 写入 `main.yml`。

## 利用步骤

1. 登录 JumpServer，进入作业中心/Playbook 管理，新建一个 Playbook（示例 pwd3）。
2. 在工作空间编辑 `main.yml`，写入带 `\u` 转义本地连接配置的恶意 Playbook（见 PoC）。
3. 保存时抓包确认 `PATCH /api/v1/ops/playbook/<uuid>/file/`，请求体 `{"key":"main.yml","content":"<恶意 YAML>"}`，服务端把文件写入 `data/ops/playbook/<uuid>/main.yml`。
4. 新建作业（type=playbook），绑定一个有效资产 ID，执行作业（`POST /api/v1/ops/jobs/execution/`），获得 task_id。
5. 打开作业日志 `/core/ops/celery/task/<task_id>/log/?type=celery` 观察执行；命令在 jms_celery 容器内执行（示例 `id > /tmp/pwnd`）。
6. 验证容器内命令落地/回显后停止测试。

## PoC

```yaml
[{
  "name": "RCE playbook",
  "hosts": "all",
  "tasks": [{
    "name": "run on celery",
    "shell": "id > /tmp/pwnd",
    "\u0064elegate_to": "localhost"
  }],
  "vars": {
    "ansible_\u0063onnection": "local"
  }
}]
```

```http
PATCH /api/v1/ops/playbook/<pk>/file/ HTTP/1.1
Content-Type: application/json

{"key":"main.yml","content":"<上面的 YAML>"}
```

说明：示例命令为无害的 `id > /tmp/pwnd`，仅验证执行位置；作业执行接口字段以实际环境为准。

## 变体与关联

- CVE-2024-29202：同一批修复里作业/模板渲染的 Jinja2 环境由 `NativeEnvironment` 改为 `SandboxedEnvironment`；该分析称其执行与绕过方式与 29201 类似（未给出细节，本卡不展开）。
- 变体：任何"先按原始文本做关键字黑名单、再交给 YAML/模板引擎做语义解析"的过滤器，都可用编码差异绕过——`\uXXXX`、`\xXX`、HTML 实体、引号/换行/注释拆分等；检查方必须解析后按语义判断，或直接禁用危险能力。
- 变体：黑名单还包括 `hosts:localhost`、`local_action`、`connection:local`，同一编码手法可用于伪造 hosts 限制。
- [[web-python-framework-fastapi-jinja2-ssti-add-api-route-memshell]]：同属 Python Web 应用把用户可控内容送进模板/执行链的 RCE 形态。
- 边界：3.10.7+ 及配套 ansible-core 中 local connection 默认禁用，普通作业无法再走本地连接；若其他内部入口显式开启 `LOCAL_CONNECTION_ENABLED`，需在该入口另找注入点。

## 检测与防御

- 检测：Playbook 文件中出现 `\uXXXX`/`\xXX` 转义的关键字、`delegate_to` 指向 localhost、`ansible_connection: local`、`local_action`；jms_celery 容器内出现由 ansible 拉起的异常 shell 进程或落地文件。
- 防御：升级到 3.10.7+ 及配套 ansible-core；不要用原始文本黑名单作为安全边界，改为 YAML/AST 解析后按语义校验并拒绝转义混淆；作业执行禁用 local connection，仅内部受控流程显式开启；收紧 Playbook 编辑与作业执行权限；容器最小权限、只读根文件系统与出站限制。
