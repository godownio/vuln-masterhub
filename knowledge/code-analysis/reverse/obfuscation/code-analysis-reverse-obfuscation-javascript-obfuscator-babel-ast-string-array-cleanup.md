---
id: code-analysis-reverse-obfuscation-javascript-obfuscator-babel-ast-string-array-cleanup
title: Electron 游戏辅助 JS 混淆还原：执行字符串数组 + Babel AST 替换、别名消除与花指令清理
type: scenario
domain: code-analysis
path: code-analysis/reverse/obfuscation
technique: javascript-obfuscator-babel-ast-string-array-cleanup
aliases:
- jsjiami.com.v7 AST 还原
- _0x 字符串数组还原
- Babel 反混淆
- 花指令清理
- 变量别名消除
- Proxy 形参美化
- Electron asar 插件逆向
tags:
- javascript
- deobfuscation
- ast
- babel
- jsjiami
- electron
- asar
- string-array
- control-flow
- reverse
cve: []
severity: low
confidence: medium
affected_versions: jsjiami.com.v7 风格样本（原文截图首行标记；未标注具体版本）
status: verified
created: '2026-11-07'
updated: '2026-11-07'
verification:
  verified_by: verifier-V236
  verified_at: '2026-11-07T09:30:48+08:00'
  notes: 已对照原文及全部 32 张图核对：app.asar/script.js 目录、jsjiami.com.v7 标记、_0x4712 字符串数组与 _0x3dea Base64+RC4 解码、变量别名消除、永真分支、_0x 重命名、Proxy 形参美化，以及 Node 调试 _0x3dea(0x186c,'LBU4')='selectSkin' 均与截图一致；已修正样本归属为 jsjiami.com.v7（原文截图标记，非 javascript-obfuscator 官方版本），并注明原文对 ?? 花指令仅识别未展开。未验证点：原文只给 Babel 片段，未复跑完整还原脚本。
---

## 一句话结论

Electron 游戏辅助插件把前端逻辑打包成 `app.asar`，其中的 `script.js` 被 jsjiami.com.v7 类工具处理成“字符串数组函数 + 解码函数 + 自执行块”的结构（样本首行带 `var _0x0d6='jsjiami.com.v7'` 标记）；在隔离环境执行字符串数组函数与解码器拿到明文，再用 Babel AST 把 `_0x3dea(索引, 密钥)` 调用替换为字符串字面量，随后迭代消除变量别名、永真/永假分支与复杂常量（原文另指出 `?? undefined` 花指令但未展开处理），重命名 `_0x` 变量并美化 Proxy 形参，即可把自动行动、自动任务等业务逻辑还原到可读状态。

## 原理

- **混淆结构**：样本首行是 `var _0x0d6='jsjiami.com.v7'` 版本标记，典型布局为字符串数组函数（如 `_0x4712`，返回 Base64 字符串数组）、解码函数（如 `_0x3dea`，内部做 Base64 解码 + RC4 类异或）、初始化自执行块（数组重排/校验），以及被混淆的主体业务自执行块。字符串访问被写成 `_0x3dea(0x158c, 'unX0')` 形式，索引与密钥分散在调用点。该结构与 javascript-obfuscator 类输出相似，但样本标记和具体解码器属于 jsjiami.com.v7 一类。
- **可执行部分先执行**：字符串数组函数与解码器是自包含的，不依赖 Electron/DOM 环境；在隔离的 Node/VM 中定义这两个函数，即可把任意 `_0x3dea(i, k)` 求值为明文。这样避免在浏览器里断点逐条看。
- **AST 替换优于正则**：Babel 解析后，`CallExpression` 的 callee 名为解码函数、两个参数都是字面量时，直接在 AST 节点上求值并 `replaceWith(stringLiteral(...))`，不会误伤同名变量或字符串内容；替换后再 `generator` 输出。
- **别名消除是前提**：混淆用花指令不断把变量重新赋值（`var a=b;`、`var c=0x...;`），如果只替换单个函数名，后续引用会指向错误的绑定。先做常量传播/别名替换：遍历 `VariableDeclarator`，当右值是标识符或字面量、且左值绑定没有被修改（`binding.constantViolations` 为空）时，把所有引用替换为右值并删除声明；这样能把 `_0x3dea`、Proxy 等关键标识符还原成稳定引用。
- **死代码/花指令**：`if("字符串"==="字符串"){...}else{...}` 是永真分支，可在 AST 上 `eval` 测试表达式后只保留对应分支；`x ?? y` 在 `x` 确定为 `undefined` 时等价于 `y`（原文识别到这类 `??` 花指令，但认为不影响阅读未展开处理）；`!![]`、`0xabc` 等复杂常量可折叠为 `true`/整数。逐步清理后，剩下的主体逻辑才可读。
- **可读性变换**：把 `_0x` 开头的全局/局部变量重命名为 `global_a`/`a` 等短名，把 Proxy 处理器 `get(target, prop, receiver)`、`set(target, prop, value, receiver)` 的形参改成语义名，能显著降低阅读成本。
- **边界**：混淆不是加密；只要解码函数可执行，字符串数组就能还原。但执行样本代码有风险（可能含反调试、环境检测、恶意外联），必须在隔离容器/VM 中运行，不能直接在宿主机 Node 里 `require` 整份样本。

## 触发条件

- 目标为 Electron 应用（`app.asar`）或普通 JS bundle，代码使用 `_0x` 命名、字符串数组函数与解码函数。
- 分析环境具备 Node.js 与 Babel 工具链（`@babel/parser`、`@babel/traverse`、`@babel/generator`、`@babel/types`），并能运行隔离的 JS 执行环境。
- 解码函数自包含或只依赖少量可模拟的全局对象；若依赖 Electron/DOM/游戏客户端注入的全局变量，需要先补齐桩。
- 样本未使用强反调试/完整性校验，或分析者能绕过（替换调试器、禁用定时器等）。

## 利用步骤

1. **解包 asar**：用 `asar extract app.asar out` 或压缩工具解出目录，定位 `script.js`、`main.js`、`renderer.js` 等入口；先确认混淆脚本的引用位置。
2. **识别结构**：格式化脚本，找出字符串数组函数（返回 Base64 字符串数组）、解码函数（含 Base64/RC4/异或）、初始化自执行块和主体自执行块；记录解码函数名与调用形式。
3. **隔离执行取数组**：在独立 Node/VM 中只加载字符串数组函数与解码函数（不要加载整份样本），调用 `_0x3dea(i, k)` 得到明文；或执行数组初始化 IIFE 后打印数组。
4. **AST 替换字符串调用**：用 Babel 解析脚本，遍历 `CallExpression`，当 callee 为解码函数、参数为字面量时求值并替换为字符串字面量：
   ```javascript
   function replace_0x(p) {
     if (p.node.callee.name === "_0x3dea") {
       const re = _0x3dea(p.node.arguments[0].value, p.node.arguments[1].value);
       p.replaceWith(tps.stringLiteral(re));
     }
   }
   ```
5. **消除变量别名**：遍历 `VariableDeclarator`，对右值为标识符或字面量、且绑定未被修改的声明，把所有引用替换为右值并删除声明；重复直到没有可替换项。
6. **清理花指令**：对 `if` 的 test 为字符串/常量二元表达式时，求值后只保留命中的分支；对 `?? undefined`、`!![]`、十六进制常量等可折叠表达式可按同一思路处理（原文对 `??` 仅识别、未展开）。
7. **重命名与美化**：把 `_0x` 变量按作用域重命名为短名；把 Proxy 的 `get/set/defineProperty` 形参改为 `target`、`prop`、`receiver`、`value` 等语义名。
8. **定位业务逻辑**：按功能 ID（如 `id:'HGX'`、`id:'taskQ'`、`id:'listQ'`）搜索 HTML/JS 绑定，结合还原后的 `switch`/`if` 阅读自动行动、自动任务、自动领取等实现；对关键函数再用 Node 桩执行验证。

## PoC

无漏洞 PoC；最小可复现是下面的 Babel 变换骨架（原文片段整理）：

```javascript
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const generator = require("@babel/generator").default;
const tps = require("@babel/types");

const code = require("fs").readFileSync("script.js", "utf8");
const ast = parser.parse(code);

traverse(ast, {
  // 1) 字符串解码调用替换
  CallExpression(p) {
    if (p.node.callee.name === "_0x3dea" &&
        p.node.arguments.length === 2 &&
        tps.isLiteral(p.node.arguments[0]) &&
        tps.isLiteral(p.node.arguments[1])) {
      const re = _0x3dea(p.node.arguments[0].value, p.node.arguments[1].value);
      p.replaceWith(tps.stringLiteral(re));
    }
  },
  // 2) 别名/常量重定义消除
  VariableDeclarator(p) {
    const n = p.node;
    if (tps.isIdentifier(n.id) &&
        (tps.isIdentifier(n.init) || tps.isLiteral(n.init))) {
      const binding = p.scope.getBinding(n.id.name);
      if (!binding || binding.constantViolations.length > 0) return;
      binding.referencePaths.forEach(r => {
        r.node.name = tps.isIdentifier(n.init)
          ? n.init.name
          : generator.default(n.init).code;
      });
      if (binding.referencePaths.length > 0) p.remove();
    }
  }
});

console.log(generator.default(ast).code);
```

说明：原文的完整脚本还包含永真 if 折叠、`??` 识别与 `_0x` 变量重命名；以上只保留最小骨架。运行前需在隔离环境中提供 `_0x3dea` 的实现。

## 变体与关联

- **变体：不同解码器**。字符串数组可能用 Base64、RC4、XOR、自定义字符表；先逆出解码函数，再按同一 AST 替换思路处理。
- **变体：控制流平坦化**。若主体被 switch 状态机打散，需要先做控制流还原（识别状态变量与 case 映射），再做字符串替换。
- **变体：Electron/游戏客户端全局依赖**。解码函数引用 `window`、`document`、游戏注入的 `SGS`/`Laya` 等对象时，需要补桩或从客户端提取对应全局，否则执行会抛 `ReferenceError`。
- **关联**：[[code-analysis-reverse-obfuscation-javascript-obfuscator-v530-string-array-extraction]]（执行数组函数+偏移替换）、[[code-analysis-reverse-obfuscation-ai-ide-assisted-js-deobfuscation]]（Node 还原 + AI IDE 语义重构）、[[code-analysis-reverse-obfuscation-xor-charcode-js-kit-static-regex-deobfuscation]]（纯常量折叠）、[[code-analysis-reverse-obfuscation-python-ast-identifier-attribute-rename]]（AST 重命名思路）。
- **边界**：原文只给出部分 Babel 片段，完整脚本未随文给出；本卡按片段整理方法，未在样本上复跑。样本首行带 `jsjiami.com.v7` 标记，并非 javascript-obfuscator 官方版本，二者字符串数组/解码器结构相近但具体解码器不同。混淆强度低时手工也能还原，AST 脚本的价值在批量与可重复。

## 检测与防御

- **对分析者**：始终在隔离容器/VM 中执行样本的解码函数，禁止直接 `require` 整份混淆脚本；限制网络与文件系统访问，防止样本反调试或外联。
- **对游戏/客户端厂商**：Electron `app.asar` 可被直接解包替换，不能把前端校验当作安全边界；对关键逻辑使用服务端校验，校验客户端包签名/哈希，检测 asar 被重新打包。
- **检测**：进程命令行出现 `asar extract`、`electron` 加载非官方 `app.asar`；游戏目录出现额外 `res`/`script.js` 插件；客户端完整性校验失败。
- **防御**：代码签名与自动更新校验、asar 完整性哈希、反调试与反注入（仅提高门槛）、服务端行为检测（自动点击/自动任务的高频请求）。
