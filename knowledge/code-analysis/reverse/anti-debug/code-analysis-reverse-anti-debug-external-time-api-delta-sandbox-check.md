---
id: code-analysis-reverse-anti-debug-external-time-api-delta-sandbox-check
title: 反沙箱：外部时间戳 API 取两次差值 + 300 秒长等待，识破时间加速/睡眠 hook 与短时分析窗口
type: scenario
domain: code-analysis
path: code-analysis/reverse/anti-debug
technique: external-time-source-delta-sandbox-check
aliases:
- 时间差反沙箱
- 外部时间戳反沙箱
- 服务器时间差值检测
- 时间加速检测变体
- sleep hook 检测
tags:
- anti-sandbox
- evasion
- windows
- malware
- time-check
- httplib
- cpp
cve: []
severity: medium
confidence: medium
status: verified
created: '2026-11-09'
updated: '2026-11-09'
verification:
  verified_by: verifier-V444
  verified_at: '2026-11-09T23:02:15+08:00'
  notes: 已对照原文核对：api.pinduoduo.com/api/server/_stm 两次取时间戳、CreateEvent+WaitForSingleObject(300000) 等 300 秒、差值 >290000 放行否则 exit 均与原文代码一致；『外部时钟不受本地 Sleep hook/加速影响』原理成立。原文未展示完整工程与接口样例，卡片已注明；『2–5 分钟分析窗口』为合理补充说明。与既有分段睡眠/时间加速卡机制不同，不重复。dup-scan.json(11-08) 早于建卡(11-09)。
---

## 一句话结论

样本先请求第三方时间接口取得服务器时间戳，`WaitForSingleObject` 等待 300 秒后再取一次，只有两次服务器时间差大于 290 秒才继续执行；沙箱若加速/跳过睡眠或伪造网络时间，差值不足即退出，同时 5 分钟长等待本身也把恶意行为拖出多数在线沙箱的短时分析窗口。

## 原理

- 沙箱为快速出结果常 hook `Sleep`/`WaitForSingleObject` 等睡眠 API，把长时间等待直接加速或跳过；仅比较“请求 sleep 的毫秒数”与“本地实测耗时”的时间加速检测（见既有卡）容易被 hook 蒙混，也可能被沙箱统一 patch 掉。
- 改用**外部可信时钟**：向第三方 HTTP 时间接口取服务器时间戳，等待后再取一次。两次响应中的时间戳差反映真实世界经过的时间，不受本地时钟调整、`Sleep` hook 或时间加速影响。
- 原文调用 `CreateEvent(NULL, TRUE, FALSE, NULL)` 创建永不置位的手动重置事件，再用 `WaitForSingleObject(hEvent, 300000)` 等满 300 秒；阈值取 290 秒，留 10 秒网络/解析容差。差值为 `api_time2 - api_time1 > 290000`（毫秒）时才返回 true 继续，否则 `exit(0)`。
- 双重作用：既检测“时间被加速/睡眠被跳过”的沙箱，又天然要求样本在分析环境中存活 5 分钟以上——多数在线沙箱只运行 2–5 分钟，长等待让真正的恶意行为落在分析窗口之外。
- 副作用：该检查依赖出网；网络不可用或时间接口返回异常时 `res` 为空或状态非 200，函数直接返回 false 退出，因此它同时充当网络连通性门控。

## 触发条件

- Windows 目标，样本可访问外部 HTTP 时间接口（原文用 `http://api.pinduoduo.com` 的 `/api/server/_stm`）；
- 沙箱存在睡眠加速/跳过、时间 hook，或分析时长不足 5 分钟；
- 检查位于敏感载荷之前，且攻击者接受“断网即不运行”的取舍；
- 真实主机网络正常时差值满足阈值，正常进入载荷逻辑。

## 利用步骤

1. 请求时间接口，从响应正文中提取数字字符拼成服务器时间戳（毫秒）。
2. 创建永不置位的手动重置事件，`WaitForSingleObject` 等待 300 秒（也可换成多段短等待，见变体）。
3. 再次请求同一接口取第二个时间戳。
4. 计算差值：大于 290000 毫秒则继续执行恶意逻辑；否则直接退出。

## PoC

```cpp
bool check_time() {
    auto url = "http://api.pinduoduo.com";
    httplib::Client cli(url);
    auto res = cli.Get("/api/server/_stm");
    std::string time_str1;
    if (res->status == 200) {
        for (char c : res->body)
            if (c >= '0' && c <= '9') time_str1 += c;
    } else {
        return false;
    }
    long long api_time1 = std::stoll(time_str1);

    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL); // 永不置位
    WaitForSingleObject(hEvent, 300000);                   // 等 300 秒
    CloseHandle(hEvent);

    res = cli.Get("/api/server/_stm");
    std::string time_str2;
    if (res->status == 200) {
        for (char c : res->body)
            if (c >= '0' && c <= '9') time_str2 += c;
    } else {
        return false;
    }
    long long api_time2 = std::stoll(time_str2);

    if (api_time2 - api_time1 > 290000) return true; // 真实时间流逝
    exit(0);                                          // 时间被加速/伪造
}
```

说明：调用方在返回 false 或触发 `exit(0)` 时即放弃恶意分支；原文未展示完整工程与接口返回值样例。

## 变体与关联

- 变体：换用 NTP、其他第三方时间 API 或多个时间源交叉校验，降低单一接口被沙箱伪造的风险。
- 变体：把一次 300 秒等待拆成多次短等待，既规避“单次长 sleep 被快进”，又叠加 hook 开销（参见既有「NtDelayExecution 分 20 次 1 秒延迟」卡）。
- 变体：本地 `GetTickCount` 与外部时间戳差值交叉比对，可同时检测时间加速与网络时间伪造。
- 关联：既有「Loader 反沙箱与反调试：时间加速、桌面/主机名与 DebugPort 检测」卡用 sleep 请求值与实测耗时比较，本卡改用外部时间源差值，不依赖本地睡眠实现；「恶意样本延迟执行与多信号条件触发」卡覆盖 uptime/时间窗门控。

## 检测与防御

- 检测：样本启动后短时间内两次访问同一时间 API 且中间长时间静默（约 5 分钟）；进程在 `WaitForSingleObject`/`CreateEvent` 后长时间无行为随即出现敏感操作；网络日志中时间接口的请求-再请求模式。
- 防御/分析侧：沙箱不加速/不跳过睡眠、允许 5 分钟以上分析时长；对时间 API 返回与真实时间一致的值（不建议伪造加速，否则会被差值识破）；可用代理统一返回可信时间并监控该模式。
- 样本侧取舍：长等待会拖慢真实目标上的执行（用户需等待 5 分钟才见载荷），且对无外网目标直接失效；时间接口的可用性和返回格式也是单点依赖。
