---
id: code-analysis-source-audit-jsp-legacy-oa-include-auth-filter
title: JSP 老 OA 未授权文件审计：用 Agent Ransack 检索缺失 common.jsp include 与 session 的 JSP，再筛 SQL 拼接
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: jsp-legacy-oa-include-auth-audit
tags:
- code-analysis
- audit
- jsp
- servlet
- authentication
- unauth
- agent-ransack
- sqli
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-V296
  verified_at: '2026-11-08T07:57:08+08:00'
  notes: 已对照原文与6张图核对：鉴权靠 JSP 顶部 include common.jsp + session，图02 为受保护 JSP（include common.jsp + SQL 拼接），图03 为无鉴权 PreviewKPQT.jsp；Agent Ransack 检索式 NOT (<%@ include file="common.jsp"%>) AND NOT (session)、*.jsp、D:\phps\ksoa\ 与候选列表（ad_reader.jsp/check.jsp/index.jsp/innerlogin.jsp/header.jsp/login.jsp 等）与图04-05 一致；ad_reader.jsp 的 SQL 拼接与图06 一致。未验证点：PoC 中 SQL sink 片段为示意性示例而非原文逐字代码，未实际运行检索/注入；原文未写 KSOA 版本；frontmatter 无 sources/source_url。dedup 仅命中自身，与 Struts2/JSF 审计卡思路不同。
url: /docs/code-analysis/static/source-audit/code-analysis-source-audit-jsp-legacy-oa-include-auth-filter/
draft: false
kb_aliases:
- JSP 未授权审计
- include 鉴权文件检索
- session 关键字筛选
- Agent Ransack 代码审计
- 老 OA 源码审计
- KSOA 审计
---

## 一句话结论

JSP+Servlet 老 OA 常用“每个受保护页面顶部 `<%@ include file="common.jsp"%>`（再加 session 判断）”做鉴权；审计时用 Agent Ransack 在源码目录对 `*.jsp` 执行 `NOT (<%@ include file="common.jsp"%>) AND NOT (session)` 之类的布尔检索，先筛出没有鉴权文件/会话检查的 JSP，再在这些文件里搜 SQL 拼接、文件操作、命令执行等 sink，就能在十分钟级别批量定位未授权 SQL 注入/上传/文件读取。

## 原理

- 老式 JSP 应用往往没有统一 Filter/Interceptor 鉴权，而是约定在每个需要登录的 JSP 顶部 include 一个公共鉴权文件（如 `common.jsp`），该文件内检查 session/登录态并在失败时跳转。
- 因此“未授权的 JSP”在源码层面有稳定特征：文件头没有 `<%@ include file="common.jsp"%>`，或没有引用 session/登录判断变量。对全量 JSP 做布尔检索即可缩小到少量候选。
- 原文使用的 Agent Ransack 支持正则、文本、文件路径限定与布尔组合，检索式：
  `NOT (<%@ include file="common.jsp"%>) AND NOT (session)`
  在 `D:\phps\ksoa\` 的 `*.jsp` 中执行，结果包括 `ad_reader.jsp`、`check.jsp`、`index.jsp`、`innerlogin.jsp`、`header.jsp`、`login.jsp` 等。
- 第二步在候选文件中搜索 SQL sink：`select`、字符串拼接（`" + 参数 + "`）、`executeQuery`、`ParamUtils.getString(request,...)`、`Database` 等；同时可搜索上传/下载/命令执行 sink。
- KSOA 这类 JSP+Servlet 应用还可以绕过 Servlet 路由，直接访问 `.jsp` 并传参调用功能代码；审计和测试时把 JSP 当入口即可。
- 该方法的局限：include 文件可能改名/多层 include/动态鉴权，`session` 关键字可能出现在无关代码；需要人工复核候选，并结合运行时验证。

## 触发条件

- 拿到目标应用源码（本例先通过 ImageUpload 上传 webshell 后打包下载）。
- 应用为 JSP+Servlet 老架构，鉴权以逐页 include/session 为主、没有统一过滤器。
- 有可用的本地全文/正则检索工具（Agent Ransack、grep、ripgrep、IDE 全局搜索）。
- 审计者能按语言/框架识别危险 sink（SQL 拼接、文件操作、命令执行、反序列化）。

## 利用步骤

1. 把源码解压到本地目录（如 `D:\phps\ksoa\`），确认 JSP 文件分布与公共鉴权文件名（如 `common.jsp`）。
2. 用 Agent Ransack 设置：文件名 `*.jsp`、查找位置源码根、勾选子文件夹、包含文本 `NOT (<%@ include file="common.jsp"%>) AND NOT (session)`。
3. 得到未授权候选 JSP 列表（`ad_reader.jsp`、`check.jsp`、`index.jsp`、`innerlogin.jsp`、`header.jsp`、`login.jsp` 等）。
4. 在候选文件中检索 SQL 相关：`select`、`executeQuery`、`ParamUtils.getString(request`、`" + `、`where`；人工确认参数是否直接拼接。
5. 对确认的端点构造注入/未授权 PoC（如 `PrintZPYG.jsp?zpjhid=1' union select ...`），运行时验证。
6. 同样方法搜索上传（`ImageUpload`、`FileOutputStream`、`filepath`/`filename`）、下载/读取、命令执行 sink，扩大战果。

## PoC

Agent Ransack 检索式：

```text
NOT (<%@ include file="common.jsp"%>) AND NOT (session)
```

文件过滤与范围：

```text
文件名: *.jsp
查找位置: D:\phps\ksoa\
勾选: 子文件夹
```

候选文件中的 SQL sink 特征（示例）：

```jsp
String KPQTID = ParamUtils.getString(request,"KPQTID","");
String sql = "select ... where id='" + KPQTID + "'";
Rs = dbc.executeQuery(sql);
```

## 变体与关联

- 变体：鉴权文件改名时，先全局搜索 `<%@ include file=` 统计被 include 最多的文件，再以其为鉴权特征；或搜索 `session.getAttribute`/`checkLogin`/`isLogin` 等。
- 变体：ASP/ASPX/PHP 老系统同样可用“公共 include/鉴权函数缺失”检索；Java 新框架则转向 Filter/Interceptor 配置审计。
- 关联：[[code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration]] 是 Java 新框架从鉴权配置枚举未授权接口的思路。
- 关联：[[web-java-component-yonyou-ksoa-unauth-jsp-sqli-multi-endpoint]] 与 [[web-java-component-yonyou-ksoa-imageupload-arbitrary-file-upload]] 是本方法在 KSOA 上的产出。

## 检测与防御

- 对审计方：把该检索纳入源码审计基线；对候选文件逐个做 sink 复核，避免只依赖关键字。
- 对防守方：不要用“每个 JSP 手动 include”做鉴权，改用统一 Filter/Interceptor 并默认拒绝；对所有 JSP 做未授权访问扫描；SQL 全量参数化；上传接口白名单与目录限制。
