# domainaudit

  

A CLI tool that performs a quick security audit on a domain.

  

## What it checks

  

| Check | Description |
|-------|-------------|
| SSL Expiry | Certificate expiration date |
| Issuer | Certificate authority |
| HSTS | Strict-Transport-Security header presence |
| X-Frame-Options | Clickjacking protection header presence |
| CSP | Content-Security-Policy header presence |

  

## Usage

  

```bash

python  domainaudit.py

```

  

## Example

  

```bash

python  domainaudit.py  github.com

```

  

## Requirements

  

```bash

pip  install  -r  requirements.txt

```

  

## TODO

- DNS records (A, MX, TXT)

- SSL expiry in days instead of raw date

- Color coded output
