# NobleDNS

**单一均衡版 · 面向中国大陆日常网络环境 · 兼容性优先**

NobleDNS 是独立维护的 DNS 过滤规则项目。项目只维护一个公开的**均衡版**，以中国大陆日常网络环境下的正常访问体验为重要设计考量，采用保守、审慎、可审计的规则维护策略。

我们的目标是在 DNS 层面减少广告、跟踪和其他不需要的域名访问，同时尽可能避免影响正常网站、应用及必要的网络服务。当前构建会从配置的通用上游快照中编译受支持的封禁规则，并非由 NobleDNS 对每一条上游域名逐条进行国内业务人工核验。我们不以规则数量最大化为目标，也不提供激进版、严格版、轻量版等多个相互竞争的订阅版本。

> **关于“国内低误杀”：** 这是 NobleDNS 的设计方向和维护优先级，不代表目前已经通过大规模实测证明了某个误杀率。项目会公开测试范围、已知限制和实际证据，不把构建成功或规则数量当成过滤效果证明。

## 订阅

**唯一主订阅地址**

https://raw.githubusercontent.com/LucentDNS/NobleDNS/main/dist/dns-filter.txt

请将此地址添加到支持 NobleDNS 规则语法的 DNS 过滤客户端中。建议保留该固定地址，经过验证的构建发布后，此地址会更新；具体刷新频率由客户端决定。

- [当前规则文件](https://github.com/LucentDNS/NobleDNS/blob/main/dist/dns-filter.txt)
- [构建清单](dist/manifest.json)
- [最新验证报告](dist/validation-report.txt)
- [正式版本发布页](https://github.com/LucentDNS/NobleDNS/releases)

## 为什么只做一个均衡版

- **兼容性优先：** 不为追求拦截数量而轻易扩大封禁范围。
- **保守拦截：** 对证据不足、影响范围不清楚的域名保持审慎，不凭域名名称猜测用途。
- **关注国内常用服务：** 重点关注账号登录、支付、银行、电商、即时通信、推送、地图、视频、CDN、软件更新及公共服务网站等场景。
- **覆盖与稳定平衡：** 在广告和跟踪防护、正常访问、规则规模及维护成本之间取平衡。
- **一个结果，统一验证：** 不拆分多个版本，避免维护力量分散、测试标准不一致和用户选择困难。

以上是维护原则和测试重点，不代表每个服务都已完成实测。详见[单一版本政策](docs/EDITION-POLICY.md)和[质量维护政策](docs/QUALITY.md)。

## 规则来源

目前正式构建只配置两个上游来源：

1. [AdGuard DNS Filter](https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt)
2. [HaGeZi Multi Normal](https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt)

这两个来源是通用型规则集，并非专门针对中国大陆服务建立的数据集。NobleDNS 执行来源级控制、语法约束和构建验证，但不代表已对每条上游规则逐条进行国内服务兼容性人工审查。NobleDNS 与上述项目没有隶属或背书关系。

## 过滤范围与边界

主订阅用于 DNS 层面的广告、跟踪、遥测及其他不需要域名的拦截。DNS 过滤无法去除所有广告，例如第一方广告、与正常内容共用域名的广告，以及直接嵌入应用或媒体内容的广告。

主订阅只包含封禁规则。上游例外规则单独保留供审查，不会未经审查就作为放行规则合并进主订阅。

## 当前验证状态

项目自动化测试覆盖规则解析、语法保留、异常输入拒绝、IDNA、重复规则、来源配置、变更漂移控制和构建产物校验。

目前尚未声称具备：

- 经代表性样本测量的真实误杀率或有效拦截率。
- 独立整理并持续维护的广告、跟踪、遥测和威胁域名基准库。
- AdGuard Android、AdGuard Home 等客户端的完整实时 DNS 兼容性测试。
- 覆盖中国大陆主流网站和应用的完整兼容性矩阵。

另有 69 条上游原样保留的 hostname-anchor 规则没有显式结束分隔符，仍需针对具体客户端专项验证。这些是公开记录的验证任务，不应被误解为已确认存在故障。详见[质量维护政策](docs/QUALITY.md)和[客户端兼容性测试计划](docs/COMPATIBILITY-TEST-PLAN.md)。

## 反馈与误杀报告

如果遇到网站或应用无法正常使用、疑似误拦截或漏拦截，请通过 [GitHub Issues](https://github.com/LucentDNS/NobleDNS/issues) 反馈。请尽可能提供：

- 精确的域名（hostname），不要只提供网站名称。
- 受影响的网站、应用及具体功能（登录、支付、推送、播放、更新等）。
- DNS 过滤客户端名称、版本和系统版本。
- 可复现的操作步骤，以及开启/关闭 NobleDNS 后的对照结果。
- 脱敏后的 DNS 查询或客户端日志证据。

请勿提交个人身份信息、账号资料、认证令牌或完整私人 DNS 日志。提交前请阅读[反馈与规则修正指南](docs/FEEDBACK.md)。

## 项目质量与维护

- [单一版本政策](docs/EDITION-POLICY.md)
- [质量与维护政策](docs/QUALITY.md)
- [DNS 客户端兼容性测试计划](docs/COMPATIBILITY-TEST-PLAN.md)
- [维护者指南](docs/MAINTAINER-GUIDE.md)
- [第三方来源与许可说明](THIRD-PARTY-NOTICES.md)
- [构建清单](dist/manifest.json)
- [验证报告](dist/validation-report.txt)

规则数量不等于过滤质量。每次重要规则变更都应有来源依据、影响评估、回归测试和可回滚记录。

## 本地构建与测试

环境要求：Python 3.12。构建和回归测试使用 Python 标准库。完整流程请参阅[维护者指南](docs/MAINTAINER-GUIDE.md)。

## 许可证

NobleDNS 原始项目代码采用 [GPL-3.0-only](LICENSE)。编译后的规则数据包含上游衍生内容，仍受适用的上游许可证及第三方条款约束，详见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
