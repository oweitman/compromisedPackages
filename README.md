# Search for Compromised NPM packages

## Execute

Please navigate to the directory containing the package-lock.json / yarn.lock / pnpm-lock.yaml file and run one of the following commands.

For iobroker, this is the directory /opt/iobroker (or, for Windows, to be added later).

### Debian/Bash

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/oweitman/compromisedPackages/main/compromised.sh)
```

```bash
bash <(wget -qO- https://raw.githubusercontent.com/oweitman/compromisedPackages/main/compromised.sh)
```

### Windows/Powershell

```powershell
iex (iwr -useb https://raw.githubusercontent.com/oweitman/compromisedPackages/main/compromised.ps1)
```
