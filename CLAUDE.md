# vphone-cli

Virtual iPhone boot tool using Apple's Virtualization.framework with PCC research VMs.

See [AGENTS.md](./AGENTS.md) for project conventions, architecture, and design system.

## Quick Reference

- **Build:** `make build`
- **Boot (headless):** `make boot`
- **Boot (DFU):** `make boot_dfu`
- **All targets:** `make help`
- **Python venv:** `make setup_venv` (installs to `.venv/`, activate with `source .venv/bin/activate`)
- **Platform:** macOS 14+ (Sequoia), SIP/AMFI disabled
- **Language:** Swift 5.10 (SwiftPM), ObjC bridge for private APIs
- **Python deps:** `capstone`, `keystone-engine`, `pyimg4` (see `requirements.txt`)
