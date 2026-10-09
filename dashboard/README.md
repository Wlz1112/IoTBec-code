# IoTBec Lab Console

This additive local Web UI uses an IS/VS/VIS workflow. Strict black-box mode builds IS only from live target responses; the vulnerability JSON is used only as VS and never injects its URI into target discovery. For hidden APIs, export a browser HAR request capture and import it as IS; captured request parameters are retained as fuzz seeds. An existing IS JSON mode remains available for offline experiments.

The upstream PoC generators are not called by this dashboard. Live mode is intended only for an isolated device or emulator that you own or are authorized to test. Preview mode is the default.

## Run

From the IoTBec repository root:

```powershell
python dashboard/server.py
```

Open <http://127.0.0.1:8765>.

The server uses only the Python standard library and expects the original repository layout to remain alongside `dashboard/`. In strict black-box and HAR modes, no target firmware, IDA database or source code is read.

## Input formats

- `VS`: select a vulnerability knowledge-base JSON containing public or locally documented vulnerability characteristics.
- `IS`: use black-box page discovery, import a browser-exported HAR JSON, or select an existing `*_page.json`/`*_IS.json` capture.
- `VIS`: the server creates matches between target IS and VS. Only matched target interfaces produce validation cases.

For hidden LuCI APIs, capture the request in a browser proxy or DevTools HAR after login. The importer removes the dynamic `;stok=...` segment for signature matching while retaining the request method, parameters, and seed values.

## LLM providers

The UI supports MiMo, OpenAI GPT, DeepSeek and Anthropic Claude. MiMo uses Xiaomi's official API at `https://token-plan-cn.xiaomimimo.com/v1` with model `mimo-v2.5-pro`. The endpoint uses MiMo's Chat Completions-compatible wire format; it does not call OpenAI. For a local server-side key, set `IOTBEC_MIMO_API_KEY` before starting the server; the key is never written to source files, task responses or reports.

The “测试连接” button sends a minimal non-streaming request. “任务中启用模型辅助” makes one bounded request for safe marker values after interface discovery; the output is filtered locally and is not treated as executable PoC code.

The “搜索并生成 JSON” panel queries the NVD 2.0 CVE API by vendor/product/version, then optionally asks the selected LLM to normalize evidence-backed fields into an IoTBec vulnerability database. Generated files are written under `code/result/generated/`; URI or parameter fields remain empty when the source does not support them. Review the generated file before using it for matching.
