# 👻 GhostMap - Smarter Recon with RustScan + Web Stack Fingerprinting

GhostMap is a Bash-driven reconnaissance tool that **supercharges RustScan** with automatic detection of **web ports**, **backend technologies**, and **reverse proxy misconfigurations**.

Whether you're doing CTFs, bug bounties, or internal red teaming, GhostMap helps you spot **path smuggling vectors** and backend leaks — fast.

---

## 🧠 Features

- ⚡ **RustScan wrapper**: Auto-runs scans, saves `.xml` + `.json` outputs
- 🌐 **Web port detection**: 80, 443, 8080, 8443, 5000, 9000, etc.
- 🔍 **Tech fingerprinting**:
  - Frontend proxies: NGINX, Apache, IIS
  - Backends: Tomcat, Jetty, Flask, WebLogic, Spring Boot, WildFly
- 🧪 **Path smuggling probe**: Sends `/;foo=bar/` to test route parsing
- 💥 **Stack leak detection**: Queries `/doesnotexist` for 404 info leaks
- 🚨 **Alerts on dangerous combos** like:
  - `NGINX → Tomcat`
  - `Apache → Tomcat`
  - `IIS → WildFly`

---

## 📦 Requirements

- [RustScan](https://github.com/RustScan/RustScan)
- Tools: `bash`, `curl`, `awk`, `grep`, `getent`
- Optional: `jq` (for JSON parsing if automating further)

---

## 🛠️ Usage

```bash
./ghostmap.sh <target-hostname>
