import json

vendor = "D-Link"
series = "DIR"
product = "DIR-816"
base_path = f"{vendor}/{series}/{product}"

# 读取两个 JSON 文件
with open(f'{base_path}/{product}_page.json', 'r', encoding='utf-8') as f:
    page_data = json.load(f)

with open(f'{base_path}/{product}_CVE.json', 'r', encoding='utf-8') as f:
    cve_data = json.load(f)

# 构建合并结果
merged_data = []

# 遍历 page_data，查找匹配项
for page_item in page_data:
    page_vendor = page_item['vendor'].lower()
    page_product = page_item['product'].lower()
    page_uri = page_item['URI'].lower()

    # 用于收集所有匹配的 CVE 项
    matched_cves = []
    for cve_item in cve_data:
        cve_vendor = cve_item['vendor'].lower()
        cve_product = cve_item['product'].lower()
        cve_uri = cve_item['URI'].lower()

        if (
            page_vendor == cve_vendor and
            page_uri == cve_uri and
            page_product in cve_product  # 模糊匹配
        ):
            matched_cves.append(cve_item)

    # 将所有匹配项依次合并
    for matched_cve in matched_cves:
        merged = {
            "CVE ID": matched_cve.get("CVE ID", ""),
            "vendor": page_item["vendor"],
            "product": page_item["product"],
            "URI": page_item["URI"],
            "form_parameter": page_item.get("form_parameter", ""),
            "form_format": page_item.get("form_format", ""),
            "button": page_item.get("button", ""),
            "navigation": page_item.get("navigation", ""),
            "vul_type": matched_cve.get("vul_type", ""),
            "function name": matched_cve.get("function name", ""),
            "parameter or argument": matched_cve.get("parameter or argument", ""),
            "POC": matched_cve.get("POC", "")
        }
        merged_data.append(merged)

# 保存结果到 AC18.json
with open(f'{base_path}/{product}.json', 'w', encoding='utf-8') as f:
    json.dump(merged_data, f, indent=4, ensure_ascii=False)
