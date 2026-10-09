import matplotlib.pyplot as plt
import pandas as pd

# 构造数据
data = {
    "Year": [2020, 2021, 2022, 2023, 2024, 2025],
    "MITRE Corporation": [79.69, 86.73, 94.40, 69.72, 51.47, 51.21],
    "VulDB": [0.00, 0.00, 0.12, 4.47, 43.48, 47.98],
    "Zero Day Initiative": [15.62, 6.64, 4.73, 22.22, 1.62, 0.00],
}

df = pd.DataFrame(data)

# 定义是否显示每个数据点的矩阵
# 行顺序对应 CNA: MITRE, VulDB, ZDI
# 列顺序对应年份: 2020, 2021, 2022, 2023, 2024, 2025
show_matrix = [
    [0, 0, 1, 1, 1, 1],  # MITRE Corporation
    [0, 0, 0, 1, 1, 1],  # VulDB
    [1, 1, 1, 1, 0, 0],  # Zero Day Initiative
]

# 绘图
plt.figure(figsize=(10, 6))
for i, cna in enumerate(["MITRE Corporation", "VulDB", "Zero Day Initiative"]):
    plt.plot(df["Year"], df[cna], marker='o', label=cna)
    for j, year in enumerate(df["Year"]):
        if show_matrix[i][j]:
            plt.text(year, df[cna][j] + 2, f"{df[cna][j]:.2f}%", ha='center', fontsize=8)

plt.title("Fig1 Trends in CVE Proportions from 3 Major CNAs Covering 4 Leading Vendors (2020–2025)")
plt.xlabel("Year")
plt.ylabel("Percentage (%)")
plt.ylim(0, 100)
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()
