<p align="center"><img src="./public/logo.png" width="60%" height="100%" alt="Logo"/></p>

---

<p align="center">
Indra is a powerful, versatile, and user-friendly Python-based network scanning and vulnerability assessment tool.
</p>

## Features

- Rapid port scanning using multiple techniques
- Integration with Shodan's InternetDB for quick results
- Fallback to Python-based scanning when InternetDB data is unavailable
- Nmap verification for enhanced accuracy
- Multiple output formats: text, JSON, and port-only
- Technology detection using Wappalyzer
- Basic vulnerability information (when available from InternetDB)

## Installation

To install Indra, follow these steps:

```bash
pip install indra
```

```bash
pip install requests json socket Wappalyzer
```

### <br>indra.py -h <br><br>

```css
python3 indra.py -h

Indra is a powerful, versatile, and user-friendly Python-based network scanning and vulnerability assessment tool.

USAGE:

    indra [flags]

POSITIONAL ARGUMENTS:

    target                The target domain, IP address, or CIDR range to scan

FLAGS:
    -p, --ports             string    Ports to scan (e.g. 22,80,443 or 21-30)
    -oX, --output-xml                 Output scan in XML format
    -oJ, --output-json                Output scan in JSON format
    -oN, --output-normal              Output scan in normal text format
    -oP, --output-port-only           Output only IP and port in format ip:port
    -iL, --input-list       string    Input from list of hosts/networks
    -h, --help                        Show this help message and exit

```

## Usage

To use Indra, run the following command:

```python
python3 indra.py 1.1.1.1

Starting Indra 1.0 ( https://github.com/R0X4R/Indra ) at 2024-00-00 00:00:00
Indra  scan report for 1.1.1.1
Host is up

Ports found: 53, 80, 443, 2082, 2083, 2086, 2087, 8443, 8880

PORT      STATE  SERVICE      VERSION      TECHNOLOGIES

53/tcp    open   domain       unknown      unknown
80/tcp    open   http         unknown      Cloudflare
443/tcp   open   https        unknown      Cloudflare
2082/tcp  open   infowave     unknown      Cloudflare
2083/tcp  open   http         unknown      Cloudflare
2086/tcp  open   gnunet       unknown      Cloudflare
2087/tcp  open   http         unknown      Cloudflare
8443/tcp  open   https-alt    unknown      Cloudflare
8880/tcp  open   cddbp-alt    unknown      Cloudflare

Scan completed in 63.36 seconds
```

### If your host has some vulnerability

```
python3 indra.py hide.ip.add.res

Starting Indra 1.0 ( https://github.com/R0X4R/Indra ) at 2024-00-00 00:00:00
Indra scan report for hide.ip.add.ress
Host is up

Ports found: 80

PORT      STATE  SERVICE      VERSION      TECHNOLOGIES
80/tcp    open   http         1.19.0       unknown


Vulnerabilities:
- CVE-2021-23017
- CVE-2023-44487
- CVE-2021-3618
```

### To get output in json

```python
python3 indra.py hide.ip.add.ress -oJ

Starting Indra 1.0 ( https://github.com/R0X4R/Indra ) at 2024-00-00 00:00:00
Indra scan report for hide.ip.add.ress
Host is up

{
    "host": {
        "status": "up",
        "address": "hide.ip.add.ress"
    },
    "ports": [
        {
            "port": "80",
            "state": "open",
            "service": "http",
            "version": "1.19.0",
            "technologies": [
                "unknown"
            ]
        }
    ],
    "start_time": "2024-00-00 00:00:00",
    "target": "hide.ip.add.ress",
    "host_status": "up",
    "duration": "33.25",
    "vulnerabilities": [
        "CVE-2021-23017",
        "CVE-2023-44487",
        "CVE-2021-3618"
    ]
}
```

## Additional Usage Examples

### Scanning Multiple Targets

You can scan multiple targets by providing a list of hosts or networks:

```bash
python3 indra.py -iL targets.txt
```

Where `targets.txt` contains a list of IP addresses or domain names.

### Scanning from Standard Input

You can also provide input directly from the command line:

```bash
echo hi.de.ip.ad | python3 indra.py
```

### Specifying Ports to Scan

To scan specific ports, use the `-p` flag:

```bash
python3 indra.py 1.1.1.1 -p 22,80,443
```

### Output Formats

Indra supports multiple output formats. Here are some examples:

- **XML Format**:
    ```bash
    python3 indra.py 1.1.1.1 -oX
    ```

- **JSON Format**:
    ```bash
    python3 indra.py 1.1.1.1 -oJ
    ```

- **Normal Text Format**:
    ```bash
    python3 indra.py 1.1.1.1 -oN
    ```

- **Port-Only Format**:
    ```bash
    python3 indra.py 1.1.1.1 -oP
    ```

<br>

## License

This project is licensed under the MIT License. To view a copy of this license, visit [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT).

The MIT License is a permissive free software license that allows users to do almost anything they want with the project, such as making and distributing closed-source versions. It also provides an express grant of patent rights from contributors to users. However, it also comes with a limitation of liability and warranty disclaimer, meaning the software is provided "as is" without any guarantees.
