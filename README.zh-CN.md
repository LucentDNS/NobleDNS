# NobleDNS

**单一均衡版 · 兼容性优先 · 独立维护**

NobleDNS 是一个面向日常使用、独立维护的 DNS 过滤规则项目，并将中国大陆网络环境作为重要设计考量。项目致力于减少广告、跟踪及其他不需要的 DNS 请求，同时尽可能保障正常网站、应用和常用服务的访问。

我们只维护一个公开的**均衡版**：一条主订阅、一套统一的维护标准。相比追求封禁数量，NobleDNS 更重视规则范围、来源透明和可复现构建。

**English: [README.md](README.md)**

## 立即订阅

**NobleDNS 均衡版 · 唯一正式订阅**

`https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt`

将此地址添加到支持 AdGuard 风格 DNS 过滤规则的客户端中即可。请保持订阅地址不变；通过验证的更新会发布到此地址。客户端实际更新时间取决于客户端自身的刷新设置。

**兼容旧订阅地址：** `https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/NobleDNS.txt`

该文件由构建流程生成，供仍在使用旧订阅地址的用户兼容使用。

## 项目特点

NobleDNS 在 DNS 层面过滤上游来源所覆盖的广告、跟踪、遥测及其他不需要的域名。

- **重视兼容性：** 登录、支付、银行、通信、消息推送、电商、地图、视频、软件更新和公共服务，是重点关注的兼容性场景。
- **保守拦截：** 优先采用范围适当、有依据的规则，不以封禁数量最大化为目标。
- **统一维护：** 只有一个公开版本，所有用户共同受益于问题修正和维护改进。
- **过程可审查：** 公开来源指纹、构建清单、验证报告和规则解析排除记录。

DNS 过滤只是网络防护的一环，无法拦截所有广告，尤其是第一方广告、与正常业务共用域名的广告，以及直接嵌入应用或媒体内容的广告。

“面向中国大陆”和“重视兼容性”代表项目的设计方向，不代表所有国内网站和应用都已经实测。在缺少具有代表性、经过独立审核的评测样本前，项目不会宣称已经测得真实世界误杀率或拦截率。

## 上游来源与规则处理

当前构建组合三个互补来源：

1. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)：广泛的 DNS 广告与跟踪防护。
2. [HaGeZi Multi Normal](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt)：均衡型通用 DNS 防护。
3. [AWAvenue 秋风规则（AdGuard 纯广告版）](https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Adguard-Only.Ads.txt)：针对 App 与智能设备广告场景的专项补充。

NobleDNS 只采用 AWAvenue 的纯广告版本，不引入其更广泛的隐私或“不受欢迎”类别，避免把遥测、推送、更新等独立类别一并混入。构建器保留受支持的 AdGuard DNS 主机名规则，包括具有固定域名后缀的通配符规则和 `$important` 修饰符；对不支持或语义不明确的语法则记录原因并排除，不擅自改写。NobleDNS 独立维护自身构建流程，与任何上游项目均无隶属或背书关系。

正式订阅由配置来源中成功解析且受支持的规则构成。对于不支持或复杂的语法，构建器会予以排除，而不是猜测含义或擅自改写。主订阅还包含解析器接受的简单上游例外规则；这些规则可能在兼容客户端中覆盖匹配的封禁规则。规则出现在上游列表中只能证明其来源，不能证明例外确有必要或范围恰当。当前正式构建继承的 11 条例外仍标记为 pending，尚未经过 NobleDNS 独立批准；具体状态见[例外规则审核登记册](data/exception-review.csv)。当前生效的例外规则也会单独列出，供用户检查。

规则数量不等于规则质量；规则进入编译结果，也不代表 NobleDNS 已对每个域名逐条人工审核。

## 构建透明度

以下自动生成文件是当前构建状态的依据，其内容会随获准上游来源的更新而变化。

- [构建清单](dist/manifest.json)：来源指纹、规则数量、构建信息和策略。
- [验证报告](dist/validation-report.txt)：自动化输出检查结果。
- [语法审计](dist/syntax-audit.json)：受支持的规则形式与语法统计。
- [解析排除记录](dist/parser-exclusions.csv)：解析器排除的上游原始行及原因。
- [当前生效的上游例外规则](dist/allowlist-active.txt)：主订阅中包含的简单例外规则。

项目设置了 50 万条规则上限、上游变化检测和自动化回归测试。这些措施用于降低构建和维护风险，但不能替代真实客户端兼容性测试，也不能替代具有代表性的真实效果评测。

## 质量政策与文档

- [安全问题报告政策](SECURITY.md)
- [贡献指南](CONTRIBUTING.md)
- [例外规则审核登记册](docs/EXCEPTION-REVIEW.md)
- [质量与维护策略](docs/QUALITY.md)
- [DNS 客户端兼容性测试计划](docs/COMPATIBILITY-TEST-PLAN.md)
- [真实效果评测方案](docs/REAL-WORLD-BENCHMARK-PLAN.md)
- [单一均衡版政策](docs/EDITION-POLICY.md)
- [问题反馈与规则修正指南](docs/FEEDBACK.md)
- [发布身份验证与最小权限配置](docs/RELEASE-AUTHENTICATION.md)
- [第三方来源与许可证说明](THIRD-PARTY-NOTICES.md)

## 问题反馈

如果网站或应用无法正常使用，请通过 [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues) 反馈，并尽可能提供：

- 准确的域名；
- 受影响的具体功能，例如登录、支付、推送、播放或更新；
- DNS 客户端名称及版本；
- 可复现的操作步骤。

如果能在解析器及其他设置保持不变的情况下，对比启用和停用 NobleDNS 的结果，将更有助于定位问题。分享日志前，请删除个人信息、账号资料、认证令牌及其他隐私数据。详见[反馈指南](docs/FEEDBACK.md)。

## 许可证

NobleDNS 项目代码采用 [GPL-3.0-only](LICENSE) 许可证。编译规则包含上游衍生内容，仍受适用的上游许可证及第三方条款约束。再分发时应遵守相关要求并保留适用声明和许可证文本，详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

订阅中出现的域名仅表示 DNS 过滤目标，不构成对相关网站或运营者的指控、认可，也不表示 NobleDNS 运营或分发相关网站及其内容。

---

构建器和回归测试使用 Python 标准库。维护工作要求 Python 3.12；本地构建与发布流程请参阅[维护者指南](docs/MAINTAINER-GUIDE.zh-CN.md)。
