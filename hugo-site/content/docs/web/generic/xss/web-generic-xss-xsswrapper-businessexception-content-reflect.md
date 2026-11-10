---
id: web-generic-xss-xsswrapper-businessexception-content-reflect
title: XSS 过滤器抛异常时把被拦截内容拼进错误消息导致反射型 XSS：MCMS XssHttpServletRequestWrapper 的「参数异常:」回显
type: scenario
domain: web
path: web/generic/xss
technique: xsswrapper-exception-message-content-reflect
tags:
- xss
- reflected
- java
- springboot
- filter
- exception
- cms
- mcms
cve: []
severity: medium
confidence: high
affected_versions: MCMS（MingSoft CMS）5.2.8（原文审计版本；其他版本未验证）
status: verified
created: '2026-11-10'
updated: '2026-11-10'
verification:
  verified_by: verifier-V464
  verified_at: '2026-11-10T15:08:45+08:00'
  notes: 已通读原文并逐张核对本地61张图：图09/10 在 /mcms/search.do 搜索框注入 script 标签后错误页显示「参数异常:」并触发 alert；图11-13 的 XssHttpServletRequestWrapper.clean 源码与卡一致（BusinessException 拼接原始 content）。未验证点：原文未给出搜索参数名，卡内 keyword 为推断；PoC 未本机复跑；frontmatter 无 sources/source_url。
url: /docs/web/generic/xss/web-generic-xss-xsswrapper-businessexception-content-reflect/
draft: false
kb_aliases:
- 参数异常 XSS
- XssHttpServletRequestWrapper
- BusinessException 拼接原始参数
- 过滤器报错回显 XSS
- MCMS search.do XSS
---

## 一句话结论

XSS 过滤器 `XssHttpServletRequestWrapper.clean()` 用 Jsoup 清洗参数后，若发现内容被改写或疑似 SQL 注入，就 `throw new BusinessException("参数异常:" + content)`，把**原始未转义参数**拼进异常消息；Spring 的 500 错误页直接展示该消息，于是 `<script>alert(1)</script>` 虽然被过滤器从正常参数链路里拦下，却从异常回显里原样输出并执行。

## 原理

- **过滤器只负责“判断”，却把原文带进了异常**：`clean(name, content)` 先 `Jsoup.clean(content, "", whitelist, outputSettings)`，再 `Parser.unescapeEntities(result, true)`；只要清洗结果与原内容不一致（`!content.equals(result)`）或 `SqlInjectionUtil.isSqlValid(content)` 判为可疑，就记录 URI/参数名并抛 `BusinessException("参数异常:" + content)`。判断逻辑没错，错在异常消息里拼接了原始输入。
- **错误页是 HTML 渲染点**：Spring Boot 的 `/error` 或全局异常处理器通常把 `BusinessException.getMessage()` 放进页面/JSON 返回；若页面以 `text/html` 渲染且未做 HTML 转义，消息里的 `<script>` 会被浏览器解析执行。过滤器保护的是“业务参数流”，异常页不在其覆盖范围。
- **为什么用 `search.do` 能打**：搜索关键词参数会经过 XSS 包装器；传入 `<script>alert(1)</script>` 时 Jsoup 清洗会移除/改写标签，触发 `content != result` 分支，异常消息携带原始 payload 返回 500 页面，浏览器执行。
- **同类模式很常见**：很多 Java 过滤器/拦截器在参数校验失败时抛 `RuntimeException("参数错误:" + value)`，再由统一异常处理器返回 HTML 错误页；只要“原始值 + 未转义 + HTML 响应”三要素齐备，就是一个反射型 XSS，WAF 只盯正常参数时容易漏。

## 触发条件

- 目标使用该 XSS 包装器/类似过滤器，且 `clean` 失败分支抛出包含原始参数的异常。
- 异常被全局处理器/错误页以 `text/html` 输出且未 HTML 转义；若返回 JSON（`application/json`）则浏览器不会执行（需配合 JSONP/内容嗅探）。
- 目标参数（如搜索 `keyword`）经过该过滤器；请求无需登录（前台搜索页即可）。
- 浏览器未启用严格 CSP 阻止内联脚本。

## 利用步骤

1. 找到经过 XSS 包装器的前台参数（本案例 `/mcms/search.do` 的搜索关键词）。
2. 在参数中放入会被 Jsoup 判定为“被改写”的 payload，如 `<script>alert(1)</script>` 或 `<img src=x onerror=alert(1)>`。
3. 观察响应：服务端返回 500，错误消息为 `参数异常:<原始 payload>`（本案例弹窗/页面中直接出现脚本）。
4. 若错误页以 HTML 渲染，脚本执行；可替换为窃取 Cookie/发起请求的 payload。
5. 若响应是 JSON，尝试让请求头 `Accept: text/html` 或寻找其它 HTML 错误页路径；无 HTML 渲染则此点不可利用。

## PoC

```http
GET /mcms/search.do?keyword=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1
Host: target
```

服务端 500 响应（示意）：

```text
参数异常:<script>alert(1)</script>
```

无独立可执行 PoC；原文在本地 MCMS 5.2.8 环境复现，错误对话框/页面中弹窗。

## 变体与关联

- 同模式变体：登录失败返回“用户名 xxx 不存在”、参数校验失败返回原始参数、上传失败回显文件名等；只要异常消息拼接用户输入且页面不转义即可。
- 与常规反射型 XSS 的区别：payload 不在正常业务响应中，而在“过滤器拦截后的异常响应”中，检测规则需要覆盖 4xx/5xx 错误页。
- MCMS 其它漏洞见 `web-java-component-mcms-*`、`web-generic-sqli-mcms-*`、`web-generic-ssti-mcms-*` 同层卡片。

## 检测与防御

- 修复：异常消息只返回固定文案/错误码，不拼接用户输入；错误页对所有动态内容做 HTML 转义；统一异常处理器按 `Accept` 返回 JSON 时也要设置 `Content-Type: application/json` 并避免 HTML 嗅探。
- 检测：对 4xx/5xx 响应体做反射检测（把请求参数值与响应体比对）；关注 `参数异常`、`BusinessException` 等错误文案中的原始输入。
- 加固：CSP 禁止内联脚本；WAF 规则覆盖错误页；安全编码规范要求“日志可记录原文，响应不得回显原文”。
