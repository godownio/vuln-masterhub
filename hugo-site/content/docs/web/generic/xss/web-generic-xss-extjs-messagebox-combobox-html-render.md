---
id: web-generic-xss-extjs-messagebox-combobox-html-render
title: ExtJS 4.2.x 组件默认 HTML 渲染 XSS：MessageBox 错误弹窗与 ComboBox displayField
type: scenario
domain: web
path: web/generic/xss
technique: extjs-messagebox-combobox-html-render-xss
tags:
- xss
- extjs
- javascript
- frontend-framework
- dom-xss
- combobox
- messagebox
- legacy-system
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V217
  verified_at: '2026-11-07T04:18:11+08:00'
  notes: 已对照原文核对：cache.js 的 getSystemParam 经 Ext.String.format 拼参入 dialog.error，enums.js 的 getStoreData 将 codeValue 拼入 name，5 张截图与 POC 一致（Ext 4.2.1.883）。未验证点：原文仅控制台级 sink 验证，未给出 URL 参数/后台字典到 sink 的完整请求级利用路径，卡内已按 medium 置信度注明。
url: /docs/web/generic/xss/web-generic-xss-extjs-messagebox-combobox-html-render/
draft: false
kb_aliases:
- ExtJS XSS
- Ext.MessageBox XSS
- ComboBox displayField XSS
- Ext.String.format 注入
- 旧版 ExtJS 组件 HTML 渲染
- dialog.error XSS
---

## 一句话结论

ExtJS 4.2.x（原文实测 4.2.1.883）的 `Ext.MessageBox`、`ComboBox` 的 `displayField`、Grid 的 `renderer`/`tpl` 等组件默认把绑定值当作 HTML 渲染；在老旧 JSP 系统中，`opendmc.dialog.error()` 把参数名经 `Ext.String.format` 拼进 `Ext.MessageBox.show({msg})`，`__enum.getStoreData()` 把枚举 `codeValue` 拼进 ComboBox 的 `name` 字段，两处都能用 `<img src=x onerror=...>` 触发脚本，是审计此类系统时应优先排查的框架级 XSS sink。

## 原理

- **组件把“文本”当 HTML**：ExtJS 4.x 为灵活性把 `Ext.MessageBox` 的 `msg`、ComboBox 的 `displayField`、Grid Column 的 `renderer`、`Ext.XTemplate` 的 `tpl` 等统一按可含 HTML 的内容处理；在 4.2.3 之前基本没有默认转义。开发者常以为弹窗文本/下拉项是纯文本，实际组件走 `innerHTML` 类渲染，`<img onerror>`、`<svg onload>` 等会自动执行。
- **MessageBox 路径**：`opendmc.cache.getSystemParam(paramName, errParamName)` 在系统参数不存在时调用：
  - `opendmc.dialog.error("缺少系统参数配置", Ext.String.format("系统中没有配置[{0}]的系统参数，参数名称[{1}]", errParamName, paramName))`；
  - `opendmc.dialog.error` 最终走 `Ext.MessageBox.show({msg: ...})`；
  - `paramName`/`errParamName` 只要含 HTML，就被当作消息内容解析。原文 POC 把 `<img src=x onerror=confirm(...)>` 作为第一个参数，弹窗中图片加载失败即触发 `onerror`。
- **ComboBox 路径**：`__enum.getStoreData(codeGroup)` 从 AJAX 返回的枚举项构造 `{abbr: key, name: (noPrefix ? "" : "["+key+"]") + value}`，其中 `value` 取 `codeValue`；ComboBox 配置 `displayField: 'name'` 后，下拉项把 `name` 当 HTML 渲染。若 `codeValue`（状态描述等可编辑字段）未过滤，恶意 HTML 会被缓存进 `__enum.enums[codeGroup]`，打开下拉框/hover 即触发。
- **为什么不是 self-XSS**：sink 本身在业务代码里，不是攻击者页面；只要存在“URL 参数 → paramName”“后台录入 → codeValue → 枚举接口”的输入路径，任意用户打开页面/下拉框就会执行。原文的控制台 POC 验证的是 sink 行为；实际外部输入路径需结合具体页面确认（这是本卡 confidence 为 medium 的原因）。
- **版本土壤**：ExtJS 4.2.x 的 MessageBox/ComboBox/GridCellRenderer 默认开启 HTML 渲染，4.2.3+ 才引入部分防护；老 JSP/内网系统长期不升级，组件级 HTML 渲染成为稳定攻击面。

## 触发条件

- 目标使用 ExtJS 4.2.x（或更早）；页面加载了对应 `ext-all.js` 等资源。
- 业务代码把用户/后台可控数据传入 `Ext.MessageBox.show({msg})`、ComboBox `displayField`、Grid `renderer`、`tpl`、`html` 等 HTML 渲染点，且未做 `htmlEncode`。
- MessageBox 路径需要命中错误分支（参数不存在等），使 `dialog.error` 被调用。
- ComboBox 路径需要攻击者能写入/影响枚举 `codeValue`（后台录入、接口参数、缓存），并诱导受害者打开下拉框。
- 页面无严格 CSP 阻止内联事件处理器（`unsafe-inline` 或未限制 `img-src` 等）。

## 利用步骤

1. **确认框架与版本**：浏览器控制台执行 `Ext.getVersion()` 或 `console.log(Ext.version)`，确认 `4.2.1.883` 一类版本；查看 `ext-all.js` 路径与版本注释。
2. **定位 sink**：在 Sources/JS 文件中搜索 `Ext.MessageBox`、`dialog.error`、`Ext.String.format`、`displayField`、`renderer`、`tpl`、`html`、`Ext.create('Ext.form.ComboBox'`；重点看参数是否来自 URL（`location.search`/`Ext.urlDecode`）、AJAX 响应或后台可编辑字段。
3. **MessageBox 验证**：在控制台调用目标函数并传入 HTML 测试串（如 `<img src=x onerror=confirm(1)>`）；若弹窗触发，确认 sink。再回溯调用方：是否有页面把 URL 参数作为 `paramName` 传入；若有，构造带 payload 的链接诱导受害者访问。
4. **ComboBox 验证**：向枚举缓存注入一个含 HTML 的 `codeValue`（控制台先验证 sink），创建/找现成 ComboBox，`displayField:'name'`，打开下拉框观察执行；实际攻击面则通过后台“状态描述/字典项”录入或对应 API 写入。
5. **确认存储与触发**：刷新页面后枚举是否仍在缓存/服务端；若持久化，则是存储型 XSS，可进一步窃取 Cookie/Token、发起 CSRF、记录键盘。
6. **清理**：删除测试枚举/字典项与缓存，避免影响业务。

## PoC

```javascript
// POC 1：MessageBox 错误弹窗 sink（控制台验证）
opendmc.cache.getSystemParam(
  '<img src=x onerror=confirm("XSS_via_getSystemParam")>',
  'Image Param'
);

// POC 2：ComboBox displayField sink（控制台验证）
__enum.enums['TEST_XSS'] = [
  { codeId: 'EVIL', codeValue: '<img src=x onerror=alert(document.domain)>' }
];
var testData = __enum.getStoreData('TEST_XSS');
var combo = Ext.create('Ext.form.ComboBox', {
  store: Ext.create('Ext.data.Store', { fields: ['abbr', 'name'], data: testData }),
  displayField: 'name',   // HTML 渲染点
  valueField: 'abbr',
  renderTo: Ext.getBody()
});
// 打开下拉框/悬停触发 <img onerror>
```

```text
# 版本确认
Ext.getVersion() -> { version: "4.2.1.883", ... }
```

说明：PoC 为原文控制台复现的结构化版本，未在本机执行；原文截图显示 MessageBox 弹窗中出现被解析的 `<img>`（onerror 触发 confirm），以及 ComboBox 代码路径与 ExtJS 4.2.1.883 版本。外部输入路径（URL 参数/后台字典录入）原文未给出完整请求级复现，需按目标系统核实。

## 变体与关联

- 变体（组件）：Grid Column `renderer`、`Ext.XTemplate`/`tpl`、ToolTip、`Ext.form.field.HtmlEditor`、`Ext.panel.Panel.html`、树节点文本等 ExtJS HTML 渲染点。
- 变体（输入）：URL 查询参数、AJAX 返回的字典/枚举值、后台可编辑的“状态描述/备注/名称”、缓存的枚举数据。
- 变体（payload）：`<img src=x onerror>`、`<svg onload>`、`<iframe srcdoc>`、HTML 实体/编码绕过简单黑名单。
- 关联：[[web-generic-xss-angularjs-sandbox-escape]]（另一类前端框架表达式/沙箱逃逸）、[[web-generic-xss-hash-route-param-jquery-html-sink]]（hash 路由参数进入 jQuery HTML sink）、[[web-generic-xss-data-iframe-postmessage-innerhtml]]（postMessage → innerHTML）、[[code-analysis-source-audit-java-auth-config-unauth-endpoint-enumeration]]（老系统审计思路）。
- 边界：升级到 4.2.3+ 或更高版本、对进入 HTML 组件的值调用 `Ext.util.Format.htmlEncode`、服务端输出编码、严格 CSP（禁止内联事件）时失效；无外部输入路径时只是 self-XSS。

## 检测与防御

- 检测（代码）：搜索 ExtJS HTML 渲染 API（`Ext.MessageBox`、`displayField`、`renderer`、`tpl`、`html`）与字符串拼接（`Ext.String.format`、`+`）；对每个渲染点回溯数据源是否可控；用浏览器控制台/自动化注入测试串验证。
- 检测（运行时）：CSP 报告、DOM 变更监控（插入的 `<img onerror>`/`<svg onload>`）、WAF 对 `onerror`/`onload`/`<svg` 的告警；审计异常弹窗/下拉框内容。
- 防御：升级 ExtJS（4.2.3+ 起有部分防护，建议升级到受支持版本）；对进入 HTML 渲染点的所有值做 `Ext.util.Format.htmlEncode` 或使用文本渲染；服务端对字典/枚举/参数名做输入校验与输出编码；启用 CSP 禁止内联脚本/事件；对老系统做前端组件安全基线审计。
