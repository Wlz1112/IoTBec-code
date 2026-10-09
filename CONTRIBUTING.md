# Contributing to IoTBec

感谢你对 IoTBec 研究代码的改进。提交改动前请：

1. 在隔离环境中复现并记录设备、固件和 Python 版本。
2. 不提交 API key、设备密码、真实网络地址、私有固件或运行日志。
3. 为匹配逻辑、数据处理和报告格式变化补充最小回归测试。
4. 运行测试和编译检查：

   ```bash
   python -m unittest discover -s tests -v
   python -m compileall -q code CVE-Clustering cve_summary dashboard tests
   ```

5. 在 Pull Request 中说明实验阶段、数据来源、预期结果和已知限制。

漏洞研究请只针对自有或明确授权的设备，并遵循协调披露流程。PoC、固件和
第三方报告可能有独立的许可证或披露限制。
