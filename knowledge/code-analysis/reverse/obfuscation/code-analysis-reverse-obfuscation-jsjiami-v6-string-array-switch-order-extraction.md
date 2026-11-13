---
id: code-analysis-reverse-obfuscation-jsjiami-v6-string-array-switch-order-extraction
title: jsjiami.com.v6 混淆逆向：字符串数组 RC4 解码器 + switch 顺序表，抠取 generateHostKey 等签名函数
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: jsjiami-v6-string-array-switch-order-extraction
aliases:
- jsjiami.com.v6
- jsjiami 反混淆
- _0x329d 解码器
- switch 顺序表混淆
- 1|11|9|3|6|7|2|0|10|5|4|12|8
- 函数抠取
- 前端签名函数还原
tags:
- obfuscation
- javascript
- deobfuscation
- jsjiami
- string-array
- rc4
- control-flow
- signature
cve: []
severity: low
confidence: high
status: verified
created: '2026-11-11'
updated: '2026-11-12'
verification:
  verified_by: verifier-V559
  verified_at: '2026-11-12T00:40:56+08:00'
  notes: 已对照原文与19张图核对：jsjiami.com.v6 标记与 _0x35ee base64 字符串数组（图15）；_0x329d 为 atob+RC4 KSA/PRGA 变体解码器、结果缓存 JtnbEp（源文件）；_0x4fb6e4['THRNZ'] 加载器（图04/08）；generateHostKey 的 switch 顺序表 1|11|9|3|6|7|2|0|10|5|4|12|8（图11，原文写死该串）；getRandom(0x64,0x3e7) 与 getRandomNum 取首段（图12/18）；generateHostMD5Key=md5(hostKey+'*#|&'+ts)（图14/16）；node 输出 rd=506/ts=1688652627468/secretkey=9c2c1ccab85a4dccc0644cd11d5ab2d3 并被 Burp 重放成功（图16/17）均一致；PoC 的域名反转分段、非末段 (sum+46)%rand、末段 sum+rand 与源码 case 4/8 一致。dedup：top 候选为 javascript-obfuscator v5.3.0 字符串数组提取卡与 jsjiami.com.v7 Babel AST 卡，混淆器版本与还原方法（手工抠取+写死顺序表 vs AST 自动替换）不同，非同链。未验证点：未复跑 Node 脚本；原文为通用技术文章，无 CVE、无受影响版本；frontmatter 无 sources/source_url（库内惯例）。
---

## 一句话结论

jsjiami.com.v6 混淆的 JS 以 `_0xodr = 'jsjiami.com.v6'` 和一大段 base64 字符串数组开头，字符串取值函数 `_0x329d(index, key)` 在内部先 atob 再用 key 做 RC4 式异或解码；业务函数通过 `_0x4fb6e4['方法名'](...)` 形式的加载器调用，并用 `switch(_0x42b2d7[_0x372dc5++])` 按固定顺序表（如 `1|11|9|3|6|7|2|0|10|5|4|12|8`）打乱控制流。逆向时不必还原整站，只需把目标函数连同其调用的 `_0x329d`/`getRandom`/`getRandomNum`/MD5 等依赖逐个抠出、补齐固定顺序表与哈希库，即可在 Node 中独立运行并复现前端签名。

## 原理

- **字符串数组 + 解码器**：文件顶部 `var _0xodr='jsjiami.com.v6', _0x35ee=[...]` 是 base64 字符串数组；`_0x329d(_0x5bdd2a, _0x214027)` 把索引参数还原成数组下标，取出 base64 字符串，再用第二个参数作 key 做 RC4 变体解码（先 atob，再初始化 256 字节 S 盒、KSA/PRGA 异或），结果缓存在 `_0x329d['JtnbEp']`。
- **加载器分发**：`_0x4fb6e4['THRNZ'](generateHostKey, _0x1b3e16)` 这类调用中，第一个参数是函数对象/名称，后续是实参；混淆器用这种"方法名 + 参数"形式隐藏真实调用关系，需结合断点或静态分析还原。
- **switch 顺序表控制流**：`generateHostKey` 的 `while(true){ switch(_0x42b2d7[_0x372dc5++]) { case '0': ... case '1': ... } }`，其中 `_0x42b2d7 = '1|11|9|3|6|7|2|0|10|5|4|12|8'.split('|')` 决定 case 执行顺序。`_0x329d('‫12','im5t')` 解出的就是这个顺序串；把它写死即可让函数按原逻辑执行。
- **依赖函数图**：目标函数还会调用 `getRandom(min,max)`、`getRandomNum(str)`、`generateHostMD5Key(...)` 等被同样混淆的函数；需要递归抠取，遇到 `_0x329d(...)` 调用先解出字符串，遇到 `_0x35ee[...]` 数组引用按解码器还原。
- **为什么只需局部还原**：分析目标是前端签名参数（rd/secretkey/token 等），不需要理解整站业务；把签名相关函数抠到 Node 沙箱执行，比对页面实际请求参数即可验证还原正确。

## 触发条件

- 目标站点使用 jsjiami.com.v6 混淆（文件头 `jsjiami.com.v6` + `_0x` 字符串数组 + atob/RC4 解码器）。
- 能在浏览器 DevTools 中下断点、单步、查看作用域变量（或可把代码粘贴到 Node 沙箱执行）。
- 需要复现的签名逻辑位于少量函数内，依赖的全局变量/函数可枚举。
- 仅在授权测试/自有系统研究中使用。

## 利用步骤

1. 浏览器 F12 → Sources/Console，搜索关键参数名（如 `secretkey`），定位到生成请求体的代码。
2. 识别混淆器：文件头 `jsjiami.com.v6`、`_0x329d` 解码器、`_0x4fb6e4` 加载器、switch 顺序表。
3. 在目标函数与 `if` 分支下断点，观察哪些条件恒真/恒假、哪些变量来自页面固定数据（如 guid/token），记录实际取值。
4. 逐个抠取函数：先复制目标函数，执行报错缺什么就按报错找 `_0x329d('索引','key')` 解出对应字符串/函数名，再抠对应函数；遇到 `_0x329d` 的解码结果固定（如顺序表字符串）可直接写死。
5. 补齐依赖：Node 环境缺 `window/atob` 时补 atob 实现；缺 `crypto` 时 `require('crypto')`；把 `_0x329d` 解码器与字符串数组一起带入沙箱。
6. 运行抠出的脚本，与浏览器实际请求的 rd/secretkey/timestamp 对比；一致后即可批量生成签名参数。

## PoC

```javascript
// 原文还原后的核心签名逻辑（jsjiami 已解开）
function generateHostKey(host) {
    var parts = host.split('.');
    var rev = '';                       // 反转域名段
    for (var i = parts.length - 1; i >= 0; i--) rev += '.' + parts[i];
    rev = rev.slice(1);
    var segs = rev.split('.');
    var rand = getRandom(0x64, 0x3e7);  // 100-999 随机数
    var out = '';
    for (var j = 0; j < segs.length; j++) {
        var sum = 0;
        for (var k = 0; k < segs[j].length; k++) sum += segs[j].charCodeAt(k);
        if (j == segs.length - 1) sum = sum + rand;
        else sum = (sum + 46) % rand;   // 46 = '.'.charCodeAt()
        out += ',' + sum;
    }
    return rand + ',' + out.slice(1);
}
function generateHostMD5Key(hostKey, ts) {
    return require('crypto').createHash('md5').update(hostKey + '*#|&' + ts).digest('hex');
}
// 原文输出示例：host=generateHostKey("www.baidu.com"); rd=host.split(',')[0]; secretkey=generateHostMD5Key(host, ts)
```

说明：`getRandom`/`getRandomNum` 等被混淆函数需按原文方法一并抠出；顺序表 `1|11|9|3|6|7|2|0|10|5|4|12|8` 可直接写死。原文在 Node 中执行还原脚本并成功得到与页面一致的 rd/secretkey。

## 变体与关联

- **变体**：jsjiami 不同版本（v6/v7）解码器常量与字符串数组布局会变；先看文件头版本标识，再按 `_0x329d` 的 atob+RC4 结构定位。
- **变体**：字符串数组可能被拆成多个、或使用 `while(!![])` + `parseInt` 洗牌；以运行时实际值为准。
- **关联**：[[code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction]]（javascript-obfuscator 的字符串数组提取）、[[code-analysis-reverse-obfuscation-baidu-translate-v2transapi-sign-restore]]（前端签名还原的完整案例）、[[code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation]]（AI 辅助反混淆）。
- **边界**：若关键逻辑在 WebAssembly/JSVMP/服务端，或存在强反调试/定时 debugger，需先处理保护；顺序表/解码结果随版本变化，不能跨版本硬编码。

## 检测与防御

- **分析侧**：先识别混淆器与版本，再按"解码器→加载器→目标函数→依赖函数"顺序局部抠取；用实际请求参数校验还原结果。
- **防御侧**：前端混淆只能提高逆向成本，不能保护密钥；签名密钥/算法应放在服务端或使用不可逆的会话绑定；对关键接口做频率限制、设备指纹与风控，避免仅依赖前端签名。
