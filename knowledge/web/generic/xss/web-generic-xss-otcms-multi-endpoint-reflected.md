---
id: web-generic-xss-otcms-multi-endpoint-reflected
title: OTCMS（网钛CMS）多处反射型 XSS：HrefEnd backURL、SendPhoneForm type、ProvCity idName 与 apiRun mode 未过滤直接回显
type: scenario
domain: web
path: web/generic/xss
technique: otcms-reflected-xss-multi-endpoint
aliases:
- OTCMS 反射型 XSS
- 网钛CMS XSS
- users_deal backURL XSS
- HrefEnd XSS
- SendPhoneForm type XSS
- getCityData idName XSS
- apiRun mode XSS
tags:
- php
- xss
- reflected
- otcms
- cms
- smarty
cve: []
severity: medium
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V578
  verified_at: '2026-11-12T12:26:01+08:00'
  notes: 已对照原文12875全文与37图(含7个gif拆帧共44帧)核对：HrefEnd/UserExit backURL、SendPhoneForm type、GetCityOptionJs idName、apiRun mode/type 四处入口、源码与请求响应截图均一致；'多处入口合并为一张产品级场景卡'与库内多处端点卡先例一致，四入口各自 PoC 独立，判为原子。验证中修正2处：strpos回退条件应为'包含usersCenter.php'；原文XSS请求截图未见Cookie。PoC未本机复跑。
---

## 一句话结论

OTCMS（网钛CMS）PHP 版存在至少四处反射型 XSS，均因参数未过滤直接拼进输出：`users_deal.php` 的 `backURL` 进入 `JS::HrefEnd` 的 `document.location.href="..."`；`wap/users/p.php` 的 `type` 原样写进 HTML 属性；`wap/users/read.php?m=getCityData` 的 `idName` 拼进 `getElementById("...")` 的 JS 字符串；`apiRun.php` 的 `mode` 拼进 `var mode = "..."`（`AutoRun`/`AutoRunBig` 两处）。

## 原理

- **XSS1（JS 字符串逃逸）**：`inc/classJS.php` 的 `HrefEnd($str)` 直接 `die('<script>document.location.href="'.$str.'";</script>')`，没有像 `AlertEnd` 那样调用 `AlertFilter()`（后者只把英文双引号替换成中文双引号，用来阻断闭合）。`users_deal.php` 的 `UserExit()` 用 `OT::GetStr('backURL')` 取值，仅当包含 `usersCenter.php` 或长度小于 5 时回退 `./`，随后 `JS::HrefEnd($backURL)`。把 backURL 设为 `#";alert(1);//`：`#` 让 `document.location.href` 跳到空锚点，`"` 闭合 JS 字符串，`;alert(1);//` 执行脚本并注释掉尾部 `";`。
- **XSS2（HTML 属性逃逸）**：`wap/users/p.php` 的 `SendPhoneForm($mode='pc')` 从 `OT::GetStr` 取 `type`、`btnId`、`phone`、`userName`，在拼 HTML 时把 `$type` 直接放进 `<input type="hidden" ... value="<?... $type ...?>">`，未做 HTML 编码。`type="><script>alert(1);</script>` 即可闭合属性并注入脚本标签。
- **XSS3（JS 上下文注入）**：`inc/classProvCity.php#GetDeal()` 读取 `idName`、`prov`；`GetCityOptionJs($idName,...)` 把 `$idName` 原样拼进 `document.getElementById("'.$idName.'")` 并 `echo` 到响应。由于响应按 HTML 渲染，`idName=<script>alert(1);</script>` 中的脚本标签会先被浏览器解析执行（即使它同时破坏了后续 JS 字符串）。
- **XSS4（JS 变量逃逸）**：`apiRun.php#AutoRun()` 取 `$mode = trim(''.@$_GET['mode'])`，最终输出 `var mode = "<?php echo($mode); ?>";`。`mode=";alert(1);//`（URL 编码 `%22;alert(1);//`）闭合字符串并执行；`AutoRunBig()` 同样把 `type` 参数拼进类似上下文。
- **共性原因**：CMS 的输出辅助方法（`JS::Write/Alert/HrefEnd`、模板里直接 echo GET 参数）只依赖"替换双引号"式的弱过滤，且只在个别方法里调用；其余方法/普通 HTML 输出点完全裸奔。

## 触发条件

- 目标运行 OTCMS PHP 版（原文审计 V7.16）；对应前台/后台入口可访问。
- 攻击者能让受害者打开构造的 URL（反射型 XSS 依赖社工或投递链接）；XSS1 在用户退出流程、XSS2/3 在 WAP 前台、XSS4 在 `apiRun.php` 自动任务页。
- 原文后台/SSRF 测试请求带有站点 Cookie（`LWTvn_userID` 等），XSS 请求截图未见 Cookie；各入口是否需要登录会话原文未明确，WAP 前台与退出页通常可直接访问。

## 利用步骤

1. 探测 `inc/classJS.php` 中未调用 `AlertFilter` 的 JS 输出方法（`HrefEnd` 等），定位调用点与可控参数。
2. XSS1：`GET /users_deal.php?backURL=%23%22%3balert(1);//`，响应中出现 `document.location.href="#";alert(1);//";`。
3. XSS2：`GET /wap/users/p.php?m=sendPhoneForm&dataID=7866&type=%22%3E%3Cscript%3Ealert(1);%3C/script%3E`。
4. XSS3：`GET /wap/users/read.php?m=getCityData&idName=%3Cscript%3Ealert(1);%3C/script%3E`。
5. XSS4：`GET /apiRun.php?mode=%22;alert(1);//&mudi=autoRun`（`AutoRunBig` 用 `mudi=autoRunBig` 与 `type` 参数）。
6. 观察弹窗/控制台执行，验证后按反射型 XSS 的常规利用（窃取 Cookie/会话、钓鱼表单、结合后台功能）扩展。

## PoC

```text
http://target/users_deal.php?backURL=%23%22%3balert(1);//
http://target/wap/users/p.php?m=sendPhoneForm&dataID=7866&type=%22%3E%3Cscript%3Ealert(1);%3C/script%3E
http://target/wap/users/read.php?m=getCityData&idName=%3Cscript%3Ealert(1);%3C/script%3E
http://target/apiRun.php?mode=%22;alert(1);//&mudi=autoRun
```

对应的不安全输出示例：

```php
// inc/classJS.php#HrefEnd
die('<script>document.location.href="'.$str.'";</script>');
// apiRun.php#AutoRun
var mode = "<?php echo($mode); ?>";
```

说明：原文用浏览器录屏（gif）展示前四处弹窗；gif 帧中弹窗可能已被关闭，但请求/响应截图可见 payload 原样进入脚本。PoC 未在本机复跑。

## 变体与关联

- 变体：同一 CMS 中所有直接 `echo $_GET/$_POST` 的模板与 JS 辅助方法都应逐一审计；`AlertFilter` 仅覆盖部分 `Alert*` 方法，替换双引号为中文引号也可被 `</script>`、`onerror` 等上下文之外的注入绕过（若输出在 HTML 属性/HTML 正文）。
- 关联：通用反射型 XSS 的上下文逃逸与编码绕过见 web/generic/xss 下相关卡；后台 XSS 可结合 CSRF/会话劫持提升危害。
- 边界：现代浏览器/服务端 CSP 可能阻断内联脚本；HttpOnly Cookie 会降低会话窃取成功率。

## 检测与防御

- 检测：请求参数中出现 `<script`、`"`、`'`、`javascript:` 等特征并被原样反射；响应中包含未编码的回显；日志中同一 IP 批量请求带 payload 的 URL。
- 防御：所有输出按上下文编码（HTML 实体、JS 字符串转义、URL 编码）；废弃 `die('<script>...')` 式字符串拼接，改用 `json_encode` 或 DOM API；给会话 Cookie 加 HttpOnly/SameSite；部署 CSP；对 XSS 输入做统一过滤与 WAF 规则。
