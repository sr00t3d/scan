[![🇺🇸 English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![🇧🇷 Português](https://img.shields.io/badge/lang-Português-green.svg)](README-ptbr.md) [![🇪🇸 Español](https://img.shields.io/badge/lang-Español-yellow.svg)](README-es.md)

# scan

![scan cover](scan-cover.webp)

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/sr00t3d/scan/releases/tag/v2.0.0)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-4.0%2B-orange.svg)](#requisitos)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20cPanel%20%7C%20Plesk-lightgrey.svg)](#requisitos)

**Escáner Híbrido ClamAV + Heurístico de Webshells con Cuarentena Segura Root-Only.**

`scan.sh` analiza cuentas cPanel/Plesk, resellers, webroots, `/tmp` y `/dev/shm` combinando **ClamAV autodetectado** con un **motor heurístico nativo en Python** (EICAR, webshells PHP, ofuscación), ejecutándose en modo solo lectura por defecto con cuarentena `0700` en `/var/quarantine/scan/` y restauración directa con `restore`.

> **Inspiración Histórica:** Reimplementación limpia en Bash + Python 3.6+ (`v2.0.0`) inspirada en `scan_2.sh` (2012, Michael Karr, HostGator.com, LLC).

---

## Ejecución Directa

```bash
curl -fsSL https://raw.githubusercontent.com/sr00t3d/scan/main/scan.sh -o scan.sh
chmod +x scan.sh
sudo ./scan.sh --path /home/percio/public_html --exit-code
```

---

## Ejemplo de Salida Real

```text
==================================================================================================
 scan.sh v2.0.0 | Scan | /tmp/scan-e2e/webroot | heuristic | 2026-11-24T02:39:46Z
==================================================================================================
SEVERITY  ENGINE     SIGNATURE                   ACTION       PATH
--------  ---------  --------------------------  -----------  --------------------------------------------------
CRITICAL  heuristic  PHP.Webshell.UserInputExec  QUARANTINED  /tmp/scan-e2e/webroot/cmd.php
CRITICAL  heuristic  EICAR-Test-Signature        QUARANTINED  /tmp/scan-e2e/webroot/eicar.txt
HIGH      heuristic  PHP.Webshell.EvalBase64     QUARANTINED  /tmp/scan-e2e/webroot/wp-content/uploads/shell.php

Summary: 4 file(s) scanned | 3 threat(s) found
Vault:   /var/quarantine/scan/20261124-023946
```

---

## Licencia

Licenciado bajo [Apache License 2.0](LICENSE).
