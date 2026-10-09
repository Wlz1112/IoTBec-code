import pandas as pd


def extract_cve_by_year(df, cve_col):
    """
    将 CVE 按年份分组
    """
    df['year'] = df[cve_col].str.extract(r'CVE-(\d{4})')[0].astype(int)
    before_2024 = df[df['year'] <= 2023]
    after_2023 = df[df['year'] >= 2024]
    return before_2024, after_2023


def process_sheet(df, cve_col='CVE ID'):
    """
    对每个 sheet 抽取固定数量的数据
    """
    before_2024, after_2023 = extract_cve_by_year(df, cve_col)
    sampled_before = before_2024.sample(n=min(75, len(before_2024)), random_state=42)
    sampled_after = after_2023.sample(n=min(50, len(after_2023)), random_state=42)
    combined = pd.concat([sampled_before, sampled_after]).drop(columns=['year'])
    return combined


def main(input_file, output_file):
    # 读取所有 sheets
    xls = pd.read_excel(input_file, sheet_name=None)
    new_data = {}

    for sheet_name, df in xls.items():
        processed_df = process_sheet(df)
        new_data[sheet_name] = processed_df.reset_index(drop=True)

    # 写入新文件
    with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
        for sheet_name, df in new_data.items():
            df.to_excel(writer, index=False, sheet_name=sheet_name)


# 示例用法
if __name__ == "__main__":
    input_path = 'CVE.xlsx'  # 原始文件名
    output_path = 'CVE_sampled.xlsx'  # 输出文件名
    main(input_path, output_path)
