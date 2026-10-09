You are a cybersecurity analyst. Your task is to fill in missing fields in a structured vulnerability report.

Here is the current structured JSON data (some fields may be empty or missing):

```json
{target_json}
```

Below is the full CVE report text extracted from a markdown file:

```
{cve_report}
```

Your goal is to fill in any missing or empty fields in the JSON using information from the CVE report.

- For the **"URI"** field: Look for URL paths mentioned in the "Proof of Concept (POC)" section of the report. These typically indicate the vulnerable request path.
- For the **"parameter or argument"** field: Look for key-value pairs, request arguments, or configuration options described in the vulnerability explanation section.

Please return a completed JSON object with all available fields filled in as precisely as possible, based on the report content.

**Only return the completed JSON object**. Do not include any explanations, code block markers, or commentary.