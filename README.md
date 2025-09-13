# XBOX Authentication using e-mail and password

Easily obtain an **XBL3.0** authorization header (XAUTH) and related Xbox tokens (Xbox token, XSTS token, XUID) from a Microsoft account email + password.  
This project demonstrates the full auth flow (Microsoft OAuth → Xbox Live RPS → XSTS → profile lookup).

---

## Features
- No need for azure application, this tool uses Microsoft's official one.
- Exchange Microsoft OAuth code for an access token
- Authenticate to Xbox Live using the RPS ticket
- Exchange Xbox token for an XSTS token and user hash (UHS)
- Build the `XBL3.0` authorization header:  `XBL3.0 x={uhs};{xsts_token}`
- Fetch profile info and extract **XUID**
- CLI-friendly: credentials can be passed via CLI args or prompted interactively

---

## Requirements
- Python **3.7+**
- [`requests`](https://pypi.org/project/requests/)

Install dependencies:
```bash
pip install requests
```

## Usage

Run with CLI arguments:
```bash
python xbox_auth.py --email email@example.com --password "Example1234"
```
