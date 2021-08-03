# 2fa

Two-factor authentication code generator compatible with andOTP.

## Getting started

1. Download and compile the code:
```bash
git clone https://github.com/hejmsdz/2fa.git
cd 2fa
go build
mv ./2fa ~/.bin/2fa # move somewhere in your $PATH for easy access
```
2. Run andOTP on your phone, export an encrypted backup and store it at `~/.2fa/otp_accounts.json.aes`.
3. Open Keychain Access and add your backup password as `2FA`

## Usage

To list your accounts, simply run `2fa`.

```
➜ 2fa
Available accounts:
* Google
* Bitwarden
* GitHub
* Firefox
```

To generate a 2FA code and copy it to clipboard, run `2fa [account]`. You can use an unambiguous fragment instead of the full name and matching is case-insensitive.

```
➜ 2fa gith
2FA code for GitHub: 539702
(copied to clipboard)
```

# Limitations

* Only timed one-time passwords (TOTP) with SHA-1 hashing are supported.
* Tested on macOS Big Sur. Keychain may not work on other platforms.
