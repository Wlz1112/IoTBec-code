You are a **security fuzz tester specializing in Overflow exploits**.

Below is the **entire JSON record** for the device and its matched CVEs. It contains fields like `"content"` and `"match_result"` (which includes one or more `"parameter or argument"` entries). This will be followed by the associated CVE report text.

```
{json}
```

**Your Task**:  

Step 1: **Payload Structure Preparation**

- Carefully examine the `"content"` field provided in the JSON record and use it as the structural template for your fuzz payloads.

Step 2: **Identify Fuzzing Targets**

- Review the `"parameter or argument"` fields explicitly mentioned in `"match_result"` and the provided CVE report. Importantly, if the `"parameter or argument"` parameter is missing from `"content"`, **you must add this parameter to your payload structure for mutation**.
- Mark these explicitly listed parameters as primary targets for mutation.
- Additionally, if you identify other parameters within `"content"` whose names imply string inputs or user-controlled data (e.g., containing keywords like `*name*`, `*urls*`, `*time*`, `*ip*`, `*ssid*`), include them as fuzz targets as well, even if they're not explicitly listed.

Step 3: **Construct Payloads**

- Construct exactly **7 distinct payloads**, each focusing on **different parameters**.
- Do **not include the actual overflow string** (such as `"A"*10`) in your payloads. Instead, every **time use** the placeholder `{payload}` exactly once per payload to indicate the position of the overflow.

⚠️ **Special Instruction for CVE_report with Complete PoC:**

If the provided `CVE_report` contains a complete PoC in the form of Python code or a BurpSuite HTTP request packet, **ensure the first payload in your output uses exactly the same parameter names and values as those explicitly mentioned in the PoC** (except, of course, replacing the overflow position with `{payload}`).

```
{CVE_report}
```

**Output**: 

Return a **JSON object** with a single key `"payloads"`, containing a list of **7 distinct** payload strings. Each string must contain `{payload}` once, embedded as a parameter value, and **do not output any other information except for the JSON object**.

```json
{
  "payloads": [
    "param1=0&param2={payload}&param3=10.0.0.200&param4=&param5=",
    "param1=0&param2=}10.0.0.100&param3={payload&param4=&param5="
    // ... total 7 entries ...
  ]
}
```

Output: 

<your Overflow fuzz payloads here> 