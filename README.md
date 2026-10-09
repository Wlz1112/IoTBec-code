# IoTBec

IoTBec 是面向授权的 IoT 设备或 QEMU 仿真环境，利用公开漏洞信息和目标设备的 Web 接口特征，构建
Vulnerability Interface Signature（VIS），再为相似接口生成定向验证用例。

项目当前包含两条工作流：

1. 数据分析与匹配工作流：CVE 信息整理、接口签名和 VIS 构建、加权模糊匹配、消融实验。
2. 本地 Dashboard 工作流：黑盒接口发现、HAR/JSON 导入、VIS 匹配和安全预览；授权实验模式可向隔离目标发送请求。

Dashboard 默认是 preview 模式，不会向目标设备发送请求。

未知漏洞不能仅凭静态 JSON 匹配确认。已知漏洞签名只能用于缩小测试范围和指导参数变异；新的漏洞必须经过目标设备或仿真环境中的 payload 执行、异常监测和人工复核。本仓库提供签名匹配和安全预览流程；是否执行 live fuzzing 取决于用户自己的隔离实验环境。

## 功能

- 抓取厂商 CVE 描述并按产品筛选。
- 使用 LLM 将 CVE 描述/报告提取为结构化 VS。
- 从接口 JSON 或 HAR 文件读取 IS。
- 使用 URI、表单参数、格式、按钮和导航信息进行加权模糊匹配。
- 生成基于匹配结果的安全 marker 用例。
- 生成 VIS 匹配结果和 URI、表单、UI 字段的消融实验结果。
- 检查未进入 VIS 的 CVE 是否具有目标接口和关键参数证据。
- 提供本地 Dashboard、任务日志、结果 JSON 和 NVD CVE 查询入口。

## 环境要求

- Python 3.10 或更高版本。
- Dashboard 本身只使用 Python 标准库。
- CVE 抓取需要 Chrome/Chromedriver 和 Selenium。
- LLM 相关脚本需要对应服务商 API key。
- Live 验证需要用户自有且隔离的 QEMU 或物理测试设备。

安装依赖：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux/macOS 激活方式：

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

运行测试：

```bash
python -m unittest discover -s tests -v
python -m compileall -q code CVE-Clustering cve_summary dashboard tests
```

## AC18 离线示例

仓库中包含 AC18 的接口签名和 VIS 数据，可直接验证匹配及消融结果。

### 1. VIS 匹配和消融实验

```powershell
python code/result/crash_reuse.py `
  --target-file code/result/Tenda/AC/AC18/AC18_page.json `
  --database code/result/Tenda/AC/AC18/AC18.json `
  --threshold 75
```

当前仓库数据的预期结果：

| 指标 | 数量 |
|---|---:|
| AC18 接口签名 | 42 |
| 至少匹配一个 CVE 的接口 | 19 |
| 接口-CVE 匹配关系 | 33 |
| VIS 中的不同 CVE | 31 |

输出目录为 `code/result/Tenda/AC/AC18/result/`，包括：

- `AC18.json`：基线匹配结果。
- `AC18_no_URI.json`：去除 URI 权重的消融结果。
- `AC18_no_form.json`：去除表单字段权重的消融结果。
- `AC18_no_button_navigation.json`：去除按钮和导航权重的消融结果。

### 2. 检查未进入 VIS 的 CVE

```powershell
python code/result/verify_unmatched_cves.py `
  --cve code/result/Tenda/AC/AC18/AC18_CVE.json `
  --vis code/result/Tenda/AC/AC18/AC18.json `
  --is code/result/Tenda/AC/AC18/AC18_page.json `
  --output code/result/Tenda/AC/AC18/result/AC18_unmatched_CVE_candidates.json
```

该检查会报告：

- `AC18_CVE.json` 中有多少条 CVE 不在 `AC18.json`。
- URI 是否精确存在于 `AC18_page.json`。
- CVE 报告中提到的关键参数是否出现在接口参数中。

当前数据中有 54 条 CVE 不在 VIS，其中 3 条满足 URI 和关键参数的结构证据：

- `CVE-2020-13394`：`/goform/SetNetControlList`，`list`。
- `CVE-2020-13393`：`/goform/saveParentControlInfo`，`deviceId`、`time`。
- `CVE-2020-13389`：`/goform/openSchedWifi`，`schedStartTime`、`schedEndTime`。

这些是“结构候选”，仍然是公开已知 CVE，不等同于新漏洞确认。报告文件为
`code/result/Tenda/AC/AC18/result/AC18_unmatched_CVE_candidates.json`。

## Dashboard

启动：

```powershell
python dashboard/server.py
```

打开 <http://127.0.0.1:8765>。

### 数据源

- `blackbox`：访问授权目标站点，登录后从 HTML 表单和页面链接发现 IS。
- `har-json`：导入浏览器导出的 HAR，保留请求方法、参数和 seed body。
- `offline-json`：导入仓库中的 `*_page.json` 或其他 IS JSON，适合离线验证。

使用 AC18 离线预览时，选择：

```text
Interface source: offline-json
Interface JSON: code/result/Tenda/AC/AC18/AC18_page.json
Database: code/result/Tenda/AC/AC18/AC18.json
Mode: preview
Threshold: 75
```

Dashboard 的匹配只使用目标接口和 VIS 的公共字段；未匹配接口不会生成 fuzz 用例。AC18 预览预期为 33 个匹配关系和 50 个安全预览用例（受默认 `max_cases` 限制）。

### API key

复制 `.env.example` 为 `.env`，只在本地填写 key：

```powershell
Copy-Item .env.example .env
```

Dashboard 支持 MiMo、OpenAI、DeepSeek 和 Anthropic。`CVE-Clustering/extract_signatures.py` 使用 `DASHSCOPE_API_KEY`。`.env` 永远不要提交到 GitHub。

## 目录结构

```text
IoTBec-code/
├── code/
│   ├── spider/                 # CVE 抓取和产品筛选
│   ├── prompt/                 # VS、fuzz 和 PoC 提示词
│   ├── cve_summary_by_llm.py   # VS 生成
│   └── result/                 # VIS、匹配结果和候选报告
├── CVE-Clustering/             # CVE 签名提取与聚类分析
├── cve_summary/                # CNA/CVE 数据分析
├── dashboard/                  # 本地 Dashboard 和 HTTP API
├── data_in_paper/              # 数据处理脚本和表格
├── fig/                        # 图表素材
├── tests/                      # 回归测试
├── Emulation_Env_Setup.md      # QEMU 网络和架构环境参考
├── requirements.txt
└── .env.example
```

## 数据格式

一个 VS/VIS 记录通常包含：

```json
{
  "CVE ID": "CVE-2024-33180",
  "vendor": "Tenda",
  "product": "AC18",
  "URI": "/goform/saveParentControlInfo",
  "form_parameter": "['deviceId', 'enable', 'time']",
  "form_format": "key-value",
  "button": "Save",
  "navigation": "Parental Control->Parental Control",
  "vul_type": "Overflow",
  "parameter or argument": "deviceId"
}
```

接口签名中的 `form_parameter` 只用于匹配参数名；具体参数值作为 fuzz seed 只应来自目标设备实际捕获的请求。

## 安全和实验边界

- 默认 Dashboard 模式是 preview，不发送请求。
- Live 模式只适用于自己拥有或明确获准测试的设备/仿真环境。
- `code/result/exec_poc.py` 会执行生成的 Python PoC，不能在生产网络运行。
- 缓冲区溢出和命令注入测试可能导致设备崩溃或不可恢复，请使用快照和隔离网络。
- 仓库中的匹配结果和结构候选不代表漏洞已被验证，也不代表 CVE 已被分配。
- 原始 PDF 文件被本地 `.gitignore` 排除；外部资料、厂商固件、第三方数据和报告可能受单独版权或使用条款约束。

## 故障排查

### `ModuleNotFoundError`

确认已激活虚拟环境并执行 `python -m pip install -r requirements.txt`。Dashboard 不需要第三方依赖，但 CVE、LLM 和聚类脚本需要额外库。

### 找不到 JSON 文件

从仓库根目录运行命令，并使用 `code/result/...` 开头的路径。`crash_reuse.py` 也支持绝对路径。

### 没有匹配结果

检查目标 IS 和 VIS 的 URI、参数、按钮、导航是否来自同一设备系列；先用 AC18 示例确认安装和数据路径正确，再调整阈值。

### LLM 调用失败

检查 `.env` 中的 key、base URL 和模型名称。LLM 返回结果只作为候选字段或安全 marker，必须审查后再用于实验。


