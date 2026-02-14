# fptnbot — FPTN VPN Manager

A one-command script to install, manage, and create users for your [FPTN VPN](https://github.com/FarazFe/fptn-manager) server using Docker.

## One-line install
```bash
curl -fsSL https://raw.githubusercontent.com/milibots/fptnbot/main/fptn-manager.sh | sudo bash
```

## Or download and run manually
```bash
curl -fsSL https://raw.githubusercontent.com/milibots/fptnbot/main/fptn-manager.sh -o fptn-manager.sh
chmod +x fptn-manager.sh
sudo bash fptn-manager.sh
```

## Features

- Easy install — auto-detects public IP, generates SSL certs, creates a user and token in one go
- Custom install — full control over ports, DNS, proxy domain, sessions, and more
- Add / delete VPN users
- Generate access tokens for existing users
- Start / stop / update the server
- SSL certificate management

## Requirements

- Linux server (Ubuntu, Debian, CentOS, Fedora)
- Root / sudo access
- Internet connection (Docker will be installed automatically if missing)

## Usage

After running the script, an interactive menu appears:
```
  1)  Easy install   (auto user + token)
  2)  Custom install (full configuration)
  3)  Start service
  4)  Stop service
  5)  Show status
  6)  View logs
  7)  Update (pull latest image)
  8)  SSL: generate certs (if missing)
  9)  SSL: show MD5 fingerprint
  10) Add VPN user (prints token)
  11) Generate token (existing user)
  12) Delete VPN user
  13) Self-install (add to PATH)
  14) Self-update  (download latest)
```

You can also use CLI flags directly:
```bash
sudo bash fptn-manager.sh --easy-install
sudo bash fptn-manager.sh --start
sudo bash fptn-manager.sh --stop
sudo bash fptn-manager.sh --status
sudo bash fptn-manager.sh --add-user
sudo bash fptn-manager.sh --gen-token
```

## License

MIT
```

---

4. Commit message: `Add README with one-line install`
5. Click **Commit changes**

---

## Step 3 — Verify the raw URL works

Open this in your browser to confirm the file is accessible:
```
https://raw.githubusercontent.com/milibots/fptnbot/main/fptn-manager.sh
