## Task

You will receive a vulnerability description. Extract (or infer) the following fields from the text and output **only** a minified JSON object with exactly these 6 keys:

```json
{
  "vendor":"{vendor}",
  "product":"{product}",
  "vul_type":"",
  "function name":"",
  "URI":"",
  "parameter or argument":""
}
```

## RULES for "vul_type":

**Only** choose one of the following **exact values**:

- "Overflow"
- "Injection"
- "CSRF"
- "other type"

**Definitions**:

- Use **"Overflow"** for any buffer overflow, stack overflow, heap overflow, etc.
- Use **"Injection"** for any code execution, command injection, SQL injection, etc.
- Use **"CSRF"** only for Cross-Site Request Forgery
- Use **"other type"** for all other vulnerabilities

If the description does not contain a value for any field, fill it with `""`.

## Example

**Description:**

```
A vulnerability, which was classified as critical, has been found in Tenda A301 15.13.08.12. Affected by this issue is the function formWifiBasicSet of the file /goform/SetOnlineDevName. The manipulation of the argument devName leads to stack-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-269948. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.
```

**Output (valid JSON only, no additional commentary):**

```json
{
  "vendor":"{vendor}",
  "product":"A301",
  "vul_type":"Overflow",
  "function name":"formWifiBasicSet",
  "URI":"/goform/SetOnlineDevName", // not /bin/httpd! that's a binary file name
  "parameter or argument":"devName"
}
```

**Return valid JSON only**, with no extra keys or commentary. Now, following the rules above, extract information from the description below:

```
{description}
```

