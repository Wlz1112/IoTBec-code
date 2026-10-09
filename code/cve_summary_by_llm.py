from openai import OpenAI
import os
from dotenv import load_dotenv
import csv
import json
from pathlib import Path
from typing import Union
from datetime import datetime


Vendor = "TP-Link"
Series = "WR"
product = "WR841ND"
model = "gpt-4"

def enrich_cve_csv(
    input_csv: Union[str, Path],
    output_csv: Union[str, Path],
    prompt_md: Union[str, Path],
    vendor: str = "",
    product: str = "",
    model: str = "",
) -> None:
    """
    读取 input_csv → 调用 LLM → 生成新列 structured (包含 CVE ID, URI, Button, Navigation, POC) → 写入 output_csv
    """
    # --- 1. 环境变量 / LLM 准备 -------------------------------------------------
    load_dotenv()
    client_options = {"api_key": os.getenv("OPENAI_API_KEY")}
    if os.getenv("OPENAI_API_BASE"):
        client_options["base_url"] = os.getenv("OPENAI_API_BASE")
    client = OpenAI(**client_options)

    input_csv, output_csv, prompt_md = map(Path, (input_csv, output_csv, prompt_md))
    if not input_csv.exists():
        raise FileNotFoundError(input_csv)
    if not prompt_md.exists():
        raise FileNotFoundError(prompt_md)

    # --- 2. 先只读整个文件，避免被“清空文件”陷阱 ---------------------------
    with input_csv.open(newline="", encoding="utf-8") as fin:
        reader = csv.DictReader(fin, restkey="__extra__")
        if reader.fieldnames is None:
            raise ValueError("❌ 输入 CSV 缺少标题行（Header）。")
        fieldnames = reader.fieldnames + ["structured"]
        rows = list(reader)

    # --- 3. 写入（可以用同一路径；也可以写 temp 再覆盖） -------------------------
    with output_csv.open("w", newline="", encoding="utf-8") as fout:
        writer = csv.DictWriter(fout, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()

        prompt_template = prompt_md.read_text(encoding="utf-8")

        for row in rows:
            # 清理掉 None / "__extra__" 之类不在 fieldnames 的键
            row = {k: v for k, v in row.items() if k in reader.fieldnames}
            description = row.get("Description", "")
            cve_id = row.get("CVE ID", "")

            user_prompt = (
                prompt_template
                .replace("{vendor}", vendor)
                .replace("{product}", product)
                .replace("{description}", description)
            )

            resp = client.chat.completions.create(
                model=model,
                temperature=0.1,
                messages=[
                    {"role": "system",
                     "content": "You are a cybersecurity analyst who extracts structured information from CVE vulnerability descriptions."},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=1200
            )

            try:
                structured_content = (
                    resp.choices[0]
                        .message.content
                        .strip()
                        .removeprefix("```json")
                        .removesuffix("```")
                )
                structured_data_unordered = json.loads(structured_content)
            except Exception:
                structured_data_unordered = {}

            # 添加新的字段
            structured_data = {"CVE ID": cve_id}
            # 字段注释示例：
            # structured_data["URI"] = "/example/path"  # Example: the vulnerable request path
            for key, value in structured_data_unordered.items():
                structured_data[key] = value
            # 保证 POC 字段存在且为空
            structured_data["POC"] = ""

            row["structured"] = json.dumps(structured_data, ensure_ascii=False)
            print(row)
            writer.writerow(row)

    print(f"✅ enrich_cve_csv 完成，结果已写入 {output_csv}")


def combine_structured_json(input_csv: Union[str, Path], output_json: Union[str, Path]) -> None:
    """
    读取 input_csv 文件，提取每一行的 'structured' 字段的 JSON 字符串，
    解析成 Python 字典，并将所有字典组成一个 JSON 数组写入到 output_json 文件。
    """
    input_csv = Path(input_csv)
    output_json = Path(output_json)

    if not input_csv.exists():
        raise FileNotFoundError(input_csv)

    all_structured_data = []
    with input_csv.open(newline="", encoding="utf-8") as fin:
        reader = csv.DictReader(fin)
        if reader.fieldnames is None or "structured" not in reader.fieldnames:
            raise ValueError("❌ 输入 CSV 文件缺少标题行或 'structured' 列。")
        for row in reader:
            s = row.get("structured")
            if not s:
                continue
            try:
                data = json.loads(s)
                all_structured_data.append(data)
            except json.JSONDecodeError:
                print(f"⚠️ 无法解析行 {reader.line_num} 的 structured 字段")

    with output_json.open("w", encoding="utf-8") as fout:
        json.dump(all_structured_data, fout, indent=4, ensure_ascii=False)

    print(f"✅ combine_structured_json 完成，结果已写入 {output_json}")


def refill_missing_fields_from_reports(
    structured_json_path: Union[str, Path],
    prompt_path: Union[str, Path],
    cve_report_dir: Union[str, Path],
    model: str = "grok-2-1212"
) -> None:
    """
    针对 structured JSON 文件中 URI 为空的条目，使用 CVE 报告和补全文本提示词填充字段。
    合并规则：已有字段保持不变，空字段用新数据补全。若对应的 MD 文件为空或不存在，则跳过补全。
    最后保证 POC 字段存在且为空。
    """
    load_dotenv()
    client_options = {"api_key": os.getenv("OPENAI_API_KEY")}
    if os.getenv("OPENAI_API_BASE"):
        client_options["base_url"] = os.getenv("OPENAI_API_BASE")
    client = OpenAI(**client_options)

    structured_json_path = Path(structured_json_path)
    prompt_path = Path(prompt_path)
    cve_report_dir = Path(cve_report_dir)

    if not structured_json_path.exists():
        raise FileNotFoundError(structured_json_path)
    if not prompt_path.exists():
        raise FileNotFoundError(prompt_path)

    structured_list = json.loads(structured_json_path.read_text(encoding="utf-8"))
    prompt_template = prompt_path.read_text(encoding="utf-8")

    updated = []
    for entry in structured_list:
        uri = entry.get("URI", "").strip()
        cve_id = entry.get("CVE ID", "").strip()

        # 仅在 URI 为空且有 CVE ID 时尝试补全
        if not uri and cve_id:
            md_file = cve_report_dir / f"{cve_id}.md"
            if not md_file.exists():
                print(f"⚠️ 找不到报告文件 {md_file}, 跳过补全")
            else:
                md_text = md_file.read_text(encoding="utf-8")
                if md_text.strip():
                    prompt = (
                        prompt_template
                        .replace("{target_json}", json.dumps(entry, ensure_ascii=False))
                        .replace("{cve_report}", md_text)
                    )
                    try:
                        resp = client.chat.completions.create(
                            model=model,
                            temperature=0.1,
                            messages=[
                                {"role": "system",
                                 "content": "You are a cybersecurity analyst who completes missing fields in structured vulnerability data."},
                                {"role": "user", "content": prompt},
                            ],
                            max_tokens=1200
                        )
                        refined = (
                            resp.choices[0]
                                .message.content
                                .strip()
                                .removeprefix("```json")
                                .removesuffix("```")
                        )
                        refined_data = json.loads(refined)
                        # 合并已有字段不变，空字段才填充
                        for k, v in refined_data.items():
                            if not entry.get(k):
                                entry[k] = v
                    except Exception as e:
                        print(f"❌ 补全失败 ({cve_id}): {e}")
                else:
                    print(f"⚠️ 报告 {md_file} 为空，跳过补全")

        # 最后保证 POC 字段存在且为空
        entry["POC"] = ""
        updated.append(entry)

    # 保存回原 JSON
    with structured_json_path.open("w", encoding="utf-8") as fout:
        json.dump(updated, fout, indent=4, ensure_ascii=False)

    print(f"✅ refill_missing_fields_from_reports 完成，结果已保存至 {structured_json_path}")


if __name__ == "__main__":
    print("当前时间是：", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    input_csv = f"./result/{Vendor}/{Series}/{product}/{product}_{Vendor.lower()}_cve.csv"
    enrich_cve_csv(
        input_csv=input_csv,
        output_csv=input_csv,
        prompt_md="./prompt/summary.md",
        vendor=Vendor,
        product=product,
        model=model
    )

    output_json_file = f"./result/{Vendor}/{Series}/{product}/{product}_CVE.json"
    combine_structured_json(
        input_csv=input_csv,
        output_json=output_json_file
    )

    refill_missing_fields_from_reports(
        structured_json_path=output_json_file,
        prompt_path="./prompt/filler.md",
        cve_report_dir=f"./result/{Vendor}/{Series}/{product}/CVE_report",
        model=model
    )
    print("当前时间是：", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
