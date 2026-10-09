import time
import re
import csv
from html import unescape
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

def get_cve_csv(Vendors, csv_file_path):
    """
    抓取指定厂商关键字的 CVE 编号与描述，并保存为 CSV 文件。
    :param csv_file_path:
    :param Vendors: 关键字字符串，例如 "Tenda"
    """
    service = Service(ChromeDriverManager().install())
    options = webdriver.ChromeOptions()
    # options.add_argument('--headless')  # 可取消注释以隐藏浏览器界面
    driver = webdriver.Chrome(service=service, options=options)

    try:
        url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={Vendors}"
        driver.get(url)
        time.sleep(3)
        page_source = driver.page_source
    except Exception as e:
        print(f"❌ 抓取失败: {e}")
        return
    finally:
        driver.quit()

    # 提取 CVE ID 和描述
    pattern = re.compile(
        r'(CVE-\d{4}-\d+)</a>.*?</td>\s*<td[^>]*>(.*?)</td>',
        re.S | re.I
    )

    records = []
    for cve_id, raw_desc in pattern.findall(page_source):
        desc = unescape(raw_desc)
        desc = re.sub(r'<[^>]+>', '', desc)
        desc = re.sub(r'\s+', ' ', desc).strip()
        records.append((cve_id, desc))

    with open(csv_file_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['CVE ID', 'Description'])
        writer.writerows(records)

    print(f'✅ 已保存 {len(records)} 条记录到 {csv_file_path}')

# 调用函数
Vendor = "TOTOLINK"
csv_file = fr"{Vendor.lower()}_cve.csv"
get_cve_csv(Vendor, csv_file)
