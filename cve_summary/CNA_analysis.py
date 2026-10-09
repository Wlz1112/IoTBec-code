import time
import re
import pandas as pd
from collections import defaultdict
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

def extract_cna_from_html(html):
    """
    从 HTML 中提取包含 'CNA:' 的 span 文本
    """
    match = re.search(r'<span[^>]*>\s*CNA:\s*(.*?)\s*</span>', html, re.IGNORECASE)
    return match.group(1).strip() if match else "Unknown"

def main():
    # 初始化浏览器
    service = Service(ChromeDriverManager().install())
    options = webdriver.ChromeOptions()
    options.add_argument('--headless')  # 可注释掉调试
    driver = webdriver.Chrome(service=service, options=options)

    # 读取 Excel 文件中所有 sheet 的 CVE ID
    excel_path = 'CVE/CVE.xlsx'
    xls = pd.ExcelFile(excel_path)
    all_cve_ids = []

    for sheet in xls.sheet_names:
        df = xls.parse(sheet)
        if 'CVE ID' in df.columns:
            all_cve_ids.extend(df['CVE ID'].dropna().astype(str).tolist())

    # 统计结构
    year_cna_counts = defaultdict(lambda: defaultdict(int))

    # 遍历 CVE ID 列表
    for idx, cve_id in enumerate(all_cve_ids):
        url = f"https://www.cve.org/CVERecord?id={cve_id}"
        try:
            driver.get(url)
            time.sleep(1.5)  # 等待加载
            html = driver.page_source
            cna = extract_cna_from_html(html)
        except Exception:
            cna = 'Exception'

        # 提取年份
        match = re.match(r'CVE-(\d{4})-', cve_id)
        if match:
            year = match.group(1)
            year_cna_counts[year][cna] += 1

        print(f"[{idx+1}/{len(all_cve_ids)}] {cve_id} → {cna}")

    driver.quit()

    # 输出结果
    print("\n=== CNA CVE Issuance Summary by Year ===")
    for year in sorted(year_cna_counts.keys()):
        total = sum(year_cna_counts[year].values())
        print(f"\nYear: {year} | Total CVEs: {total}")
        for cna, count in sorted(year_cna_counts[year].items(), key=lambda x: x[1], reverse=True):
            percent = count / total * 100
            print(f"  {cna}: {count} CVEs ({percent:.2f}%)")

if __name__ == "__main__":
    main()