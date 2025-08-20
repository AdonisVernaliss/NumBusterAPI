# NumBusterAPI

> **Disclaimer**  
> For educational/research use on your own device/account only. Respect laws & ToS. No warranties.

---

## What this is

Sends app-like requests to NumBuster API endpoints.
- Reads auth params from creds.json (access_token, cnonce, signature, timestamp).
- Calls multiple endpoints (ping, search, theoscope tiers, etc).
- Outputs only useful OSINT fields (name, carrier, region, flags).

**This is not an official SDK.** It’s a protocol exploration helper for legitimate testing and research on your own account/device.

---

## Quick start

```bash
# 1. Clone repo
git clone https://github.com/AdonisVernaliss/NumBusterAPI.git
cd NumBusterAPI

# 2. Create venv
python3 -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate

# 3. Install deps
pip install -r requirements.txt

# 4. Create creds.json
cp creds.example.json creds.json
```
`cred.py` is git-ignored and must not be committed.

---

## Configure (`creds.json`)
Fill in your legally obtained values:
```bash
{
  "access_token": "xxxxxxxxxxxxxxxxxxxx",
  "cnonce": "xxxxxxxxxxxxxxxxxxxx",
  "signature": "xxxxxxxxxxxxxxxxxxxx",
  "timestamp": "1755677347"
}
```

- These values rotate and are tied to your own session/device.
- Never commit creds.json (already git-ignored).

---

## Where to get the values
	Access token / cnonce / signature / timestamp → intercept from your own device traffic (e.g. Burp, mitmproxy).
	Values are session-bound, expire often — refresh them as needed.
	Never publish or reuse someone else’s credentials.

---

## Run
```bash
python NumbusterAPI.py +7*********
```
## Output example:

<img width="410" height="158" alt="Image" src="https://github.com/user-attachments/assets/bd646398-b561-4f06-9244-2eab5da07d0f" />

---

## Troubleshooting (short)
- 401 Unauthorized → creds expired → refresh via Burp capture.
- Empty profile → number not in DB.
- Connection errors → check VPN / proxy.
