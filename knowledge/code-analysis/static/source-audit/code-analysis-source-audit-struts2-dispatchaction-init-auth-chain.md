---
id: code-analysis-source-audit-struts2-dispatchaction-init-auth-chain
title: Struts2 DispatchAction 继承链鉴权审计：沿 execute→init 覆写链找出未授权 Action 与 JSP 直连入口
type: scenario
domain: code-analysis
path: code-analysis/static/source-audit
technique: struts2-dispatchaction-init-auth-chain-audit
aliases:
- Struts2 继承式鉴权审计
- CommonAct init 鉴权
- DispatchAction execute init
- 未授权 Action 定位
- super.init 漏调用
- JSP 直连绕过 Action 鉴权
tags:
- code-audit
- java
- struts2
- authentication
- access-control
- unauth
- source-audit
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V248
  verified_at: '2026-11-07T13:18:14+08:00'
  notes: 已对照原文与 28 张图核对：CommonAct extends DispatchAction 的 execute→init、ContractEdiPopupAct.init→super.init→CommonCountAct.init 校验 ssCustId、ActionNot/XssFilter 等均与图 3-13 一致；正文引用 file_show_irs.jsp 的事实与图 23 一致。核实修正：卡内指向已 reject 的 jsp-filedown 草稿的 wiki 链接已改为既有同类卡 web-generic-file-inclusion-luckyframeweb-download-filename-traversal。未验证点：方法卡未独立构造未授权 Action；原文仅以 file_show_irs.jsp 作为前台入口示例。
---

## 一句话结论

老 Struts2 项目常把鉴权写在顶级 Action 的 `execute()` 所调用的 `init()` 中；审计时先定位顶级 `CommonAct extends DispatchAction` 的 `execute()`，再沿每个业务 Action 的 `init()` 覆写链判断是否最终调用到带 session 校验的父类 `init()`——凡覆写 `init()` 未调用 `super.init()`、或在 `execute()` 中提前返回的 Action 就是未授权面；同时必须单独枚举 Web 根下可直连、内含业务逻辑且未做鉴权的 JSP，因为它们根本不进入 Action 继承链。

## 原理

- **Struts2 分发**：`.do?method=xxx` 由 `struts-config.xml` 的 `<action>` 映射到 Action 类；`DispatchAction` 按 `method` 参数分发到对应业务方法。框架调用 `execute()`，若子类未实现会沿继承链向上查找。
- **鉴权藏在 init**：顶级 `CommonAct` 重写 `execute()`，先调用 `this.init(mapping, form, request, response)`，返回非 null 则直接返回（跳转），否则调用 `super.execute()`。真正的登录校验在 `CommonCountAct.init` 中：从 session 取 `ssCustId`，为空则返回“需要登录”并跳转登录页。
- **动态分派决定实际鉴权路径**：Java 的虚方法分派会调用最派生类的 `init()`。若业务 Action 自己覆写 `init()` 且没有 `super.init(...)`，鉴权代码永远不会执行；若覆写后调用了 `super.init(...)`，则继续向上到 `CommonCountAct.init` 才有校验。
- **为什么这类项目容易漏**：鉴权依赖继承链而非过滤器/拦截器，新增 Action 或覆写 `init()` 时很容易漏掉 `super` 调用；另外 JSP 直接放在 Web 根，`web.xml` 过滤器只做编码/XSS/日志，直接请求 JSP 不经过 Action，因此完全没有鉴权。
- **审计收益**：按此方法可以快速区分“有鉴权的业务方法”和“前台方法”，并把 JSP 直连入口纳入同一张未授权面清单。

## 触发条件

- 目标为 Struts2 `DispatchAction` 架构，存在统一父类 Action（如 `CommonAct`/`CommonCountAct`）并在 `execute()` 中调用 `init()`。
- 能获取反编译源码或 class/jar（源码泄露、备份包、JDGUI/CFR 反编译）。
- 存在覆写 `init()` 未调用 `super.init()` 的业务 Action，或存在 Web 根下直接可访问且无鉴权的业务 JSP。
- 鉴权仅依赖 Action 继承链，没有额外的全局 Filter/Interceptor 覆盖所有入口。

## 利用步骤

1. 反编译 `WEB-INF/classes` 与依赖 jar，恢复 Action/Service/DAO 源码。
2. 读 `web.xml`，列出过滤器及其 URL 映射，确认哪些只做编码、XSS、日志，哪些真正做鉴权。
3. 读 `struts-config.xml`，建立 `.do` / `.action` 路径到 Action 类与 `method` 的映射。
4. 搜索 `extends DispatchAction` 定位顶级 Action，读其 `execute()` 与 `init()`，确认鉴权代码所在父类。
5. 对每个业务 Action 沿继承链解析 `init()`：是否覆写、是否调用 `super.init()`、是否最终到达带 `session.getAttribute("ssCustId")` 等校验的 `init()`。
6. 同时枚举 Web 根下的 JSP，检查是否含文件下载、SQL 查询、上传等业务逻辑且没有 include 鉴权片段。
7. 对判定为未授权的 Action/JSP，构造请求验证；将可复用的危险 sink（`new File(request.getParameter(...))`、SQL 拼接、上传）与未授权入口组合成完整链。

## PoC

审计命令示例：

```bash
# 定位顶级 Action 与 init 覆写
rg -n "extends\s+DispatchAction|ActionForward\s+init\s*\(|super\.init\s*\(" src/
# 定位鉴权校验点
rg -n "ssCustId|getSession\(\)|common_NeedLogin|sendRedirect" src/
# 定位 Web 根下 JSP 直连入口
rg -n "getParameter\(|new File\(|FileInputStream|executeQuery" webapp/ --glob '*.jsp'
```

判定示例（原文）：

```text
ContractEdiPopupAct.broker
  → CommonAct.execute()
    → this.init(...)  // 动态分派到 ContractEdiPopupAct.init
      → super.init(...)  // CommonCountAct.init 校验 session ssCustId
```

若某 Action 的 `init()` 直接 `return null` 或只做业务初始化而不调用 `super.init(...)`，则其所有 method 均为未授权面。原文另一类前台入口是 `file_show_irs.jsp`，直接 `request.getParameter("filedown")` 读文件；同类“下载接口参数直入文件路径”的任意文件读取见 [[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]。

## 变体与关联

- **鉴权位置变体**：鉴权可能写在 `execute()` 开头、`init()`、Struts2 `Interceptor` 或 Servlet `Filter` 中；审计时先确定“唯一必经点”，再检查每个入口是否绕过。
- **配置白名单审计**：Spring/Shiro 项目可用 `filterChainDefinitionMap`、excludePaths 等配置枚举匿名路径，见 [[code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration]]。
- **其他老框架**：JSF 项目可用 `ExtAbstractManagedBean`、`*.jsf→*.jsp` 路由做类似审计，见 [[code-analysis-source-audit-jsf-legacy-oa-audit]]。
- **成果落地**：原文由此找到未授权 JSP 任意文件读取（`file_show_irs.jsp?filedown=`，同类下载接口参数直入文件路径见 [[web-generic-file-inclusion-luckyframeweb-download-filename-traversal]]），再用 Tray 参数 SQL 注入（[[web-generic-sqli-struts2-tray-searchcode-concat]]）和后台文件上传完成利用。

## 检测与防御

- 不要用继承链承载鉴权：改用全局 Filter/Struts2 Interceptor 覆盖所有 Action 与 JSP，默认拒绝未显式放行的入口。
- 代码规范：覆写 `init()`/`execute()` 必须调用 `super`，或用模板方法 + final 修饰防止绕过；代码评审将“新增 Action 未继承鉴权基类”列为阻断项。
- 将业务 JSP 移入 `WEB-INF`，禁止直接访问；对 `*.jsp` 也加鉴权过滤器。
- 审计工具：对 `DispatchAction` 子类的 `init()` 覆写链做调用图分析，标记未到达鉴权方法的 Action；对 Web 根 JSP 做危险 sink 扫描。
