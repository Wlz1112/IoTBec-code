import pandas as pd
import re


def filter_cve_data(DataFrame, year_range=(2020, 2025), keyword_list=None, output_csv_path=None):
    """
    筛选 CVE 数据并可选地保存为 CSV。

    参数:
        df (pd.DataFrame): 包含 'CVE ID' 和 'Description' 列的 DataFrame。
        year_range (tuple): 包含起止年份的元组 (start_year, end_year)。
        keyword_list (list): 包含需匹配的关键字列表。
        output_csv_path (str): 如果提供路径，将筛选结果保存为该 CSV 文件。

    返回:
        pd.DataFrame: 筛选后的 DataFrame。
    """
    if keyword_list is None:
        keyword_list = []

    # 使用正则匹配 CVE ID 年份范围
    pattern = rf'^CVE-({"|".join(str(year) for year in range(year_range[0], year_range[1] + 1))})-\d+$'
    cve_filter = DataFrame['CVE ID'].str.match(pattern)

    # 匹配 Description 中是否包含关键字
    keyword_filter = DataFrame['Description'].str.contains('|'.join(map(re.escape, keyword_list)), case=False, na=False)

    # 同时满足两个筛选条件
    filtered_df = DataFrame[cve_filter & keyword_filter]

    # 可选地保存为 CSV
    if output_csv_path:
        filtered_df.to_csv(output_csv_path, index=False)

    return filtered_df

if __name__ == "__main__":
    vendor = "TP-Link"
    series = "WR"
    keywords = ["WR841ND"]
    product = keywords[0]
    csv_file = fr"../result/{vendor}/{vendor.lower()}_cve.csv"
    output_file = fr"../result/{vendor}/{series}/{product}/{product}_{vendor.lower()}_cve.csv"
    df = pd.read_csv(csv_file)
    filter_cve_data(df, year_range=(2020, 2025), keyword_list=keywords, output_csv_path=output_file)
