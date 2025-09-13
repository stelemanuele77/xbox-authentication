import requests
import re
from urllib.parse import parse_qs
import argparse
import getpass
import sys


URL_MS_OAUTH_AUTHORIZE = "https://login.live.com/oauth20_authorize.srf"
URL_MS_OAUTH_REDIRECT = "https://login.live.com/oauth20_desktop.srf"
URL_XBL_AUTHENTICATE = "https://user.auth.xboxlive.com/user/authenticate"
URL_XSTS_AUTHORIZE = "https://xsts.auth.xboxlive.com/xsts/authorize"
URL_XBL_PROFILE = "https://profile.xboxlive.com/users/me/profile/settings"



def parse_credentials():
    parser = argparse.ArgumentParser(description="Script that needs Microsoft credentials")
    parser.add_argument("--email", "-e", help="Account email / login", required=False)
    parser.add_argument("--password", "-p", help="Account password", required=False)
    args = parser.parse_args()

    email = args.email
    password = args.password
    if not email:
        try:
            email = input("Email: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInput cancelled", file=sys.stderr)
            sys.exit(1)
    if not password:
        try:
            password = getpass.getpass("Password: ")
        except (EOFError, KeyboardInterrupt):
            print("\nInput cancelled", file=sys.stderr)
            sys.exit(1)
    if not email or not password:
        parser.print_help()
        print("\nError: both email and password are required. You can pass them via --email and --password", file=sys.stderr)
        sys.exit(2)

    return {"email": email, "password": password}

credentials = parse_credentials()

params = {
    "client_id": "000000004C12AE6F",
    "redirect_uri": URL_MS_OAUTH_REDIRECT,
    "response_type": "token",
    "scope": "service::user.auth.xboxlive.com::MBI_SSL"
}
print("Requesting PPFT and URL..")
resp = requests.get(URL_MS_OAUTH_AUTHORIZE, params=params)
html = resp.text

ppft_match = re.search(r'name=\\"?PPFT\\"?[^>]*value=\\"([^"\\]+)\\"', html, re.IGNORECASE)
ppft = ppft_match.group(1) if ppft_match else None
url_post_match = re.search(r'["\']urlPost["\']\s*:\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
url_post = url_post_match.group(1) if url_post_match else None
cookie = "; ".join([f"{c.name}={c.value}" for c in resp.cookies])
if ppft and url_post:
    print("Done!")
else:
    raise Exception("Cannot get PPFT or URL")


data = {
    "login": credentials["email"],
    "loginfmt": credentials["email"],
    "passwd": credentials["password"],
    "PPFT": ppft,
}
headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    "Cookie": cookie,
}
print("Authenticating with MICROSOFT...")
login_resp = requests.post(url_post, data=data, headers=headers, allow_redirects=False)

if login_resp.status_code != 302:
    raise Exception("The authentication has failed: INVALID_CREDENTIALS_OR_2FA_ENABLED")

location = login_resp.headers.get("Location", "")
if "#" not in location:
    raise Exception("The authentication has failed: MISSING_HASH_PARAMETERS")

hash_fragment = location.split("#", 1)[1]
params = parse_qs(hash_fragment)

output = {}
for key, value in params.items():
    val = value[0] if value else None
    if key == "expires_in":
        output[key] = int(val) if val else None
    else:
        output[key] = val

if not output.get("refresh_token"):
    output["refresh_token"] = None

#print("Auth result:", output)
access_token = output.get("access_token")
if not access_token:
    raise Exception("No access_token found in authentication output")


print("Authenticated successfully!")

payload = {
    "Properties": {
        "AuthMethod": "RPS",
        "SiteName": "user.auth.xboxlive.com",
        "RpsTicket": f"t={access_token}"
    },
    "RelyingParty": "http://auth.xboxlive.com",
    "TokenType": "JWT"
}

xbox_headers = {
    "Content-Type": "application/json",
    "X-Xbl-Contract-Version": "1"
}
print("Authenticating with XBOX...")
xbox_resp = requests.post(URL_XBL_AUTHENTICATE, json=payload, headers=xbox_headers)

#print("Xbox status:", xbox_resp.status_code)
#print("Xbox response:", xbox_resp.json())

xbox_json = xbox_resp.json()
xbox_token = xbox_json.get("Token")
if not xbox_token:
    raise Exception("No Xbox User Token found in response")

print("Authentication success!")
xsts_payload = {
    "RelyingParty": "http://xboxlive.com",
    "TokenType": "JWT",
    "Properties": {
        "UserTokens": [xbox_token],
        "SandboxId": "RETAIL"
    }
}

xsts_headers = {
    "Content-Type": "application/json",
    "X-Xbl-Contract-Version": "1"
}
print("Authorizing XBOX with XSTS...")
xsts_resp = requests.post(URL_XSTS_AUTHORIZE, json=xsts_payload, headers=xsts_headers)

#print("XSTS status:", xsts_resp.status_code)
#print("XSTS response:", xsts_resp.json())

xsts_json = xsts_resp.json()
xsts_token = xsts_json.get("Token")

uhs = None
if "DisplayClaims" in xsts_json and "xui" in xsts_json["DisplayClaims"]:
    if len(xsts_json["DisplayClaims"]["xui"]) > 0:
        uhs = xsts_json["DisplayClaims"]["xui"][0].get("uhs")

if not xsts_token or not uhs:
    raise Exception("Missing XSTS token or user hash (uhs) in response")

auth_header = f"XBL3.0 x={uhs};{xsts_token}"

print("Authentication success!")
print("Token:", auth_header)


headers = {
    "Authorization": auth_header,
    "x-xbl-contract-version": "2",
    "Accept": "application/json"
}

profile_resp = requests.get(URL_XBL_PROFILE, headers=headers)
profile_json = profile_resp.json()
xuid = profile_json["profileUsers"][0]["id"]
print("XUID:", xuid)

#print("Profile status:", profile_resp.status_code)
#print("Profile response:", profile_resp.json())
