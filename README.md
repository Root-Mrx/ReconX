# ReconX
ReconX is an automated subdomain enumeration tool for security researchers. It gathers subdomains from multiple sources, cleans and verifies live ones using dnsx, detects wildcard DNS, and generates new subdomains with dnsgen. Supports single or multiple domains and custom wordlists.


  ascii_art = r"""
     _____                     __   __
    |  __ \                    \ \ / /
    | |__) |___  ___ ___  _ __  \ V / 
    |  _  // _ \/ __/ _ \| '_ \  > <  
    | | \ \  __/ (_| (_) | | | |/ . \ 
    |_|  \_\___|\___\___/|_| |_/_/ \_\
                      
                            1.2
    """


Requirements and Setup
Required External Tools
This project depends on the following external tools. Please install them before running the tool:

subfinder:
```copy
Install and setup instructions: https://github.com/projectdiscovery/subfinder
```
assetfinder:
```copy
Install and setup instructions: https://github.com/tomnomnom/assetfinder
```
dnsx:
```copy
Install and setup instructions: https://github.com/projectdiscovery/dnsx
```
dnsgen:
```cppy
Install and setup instructions: https://github.com/ProjectDiscovery/dnsgen
```
httpx (optional, for extended HTTP probing):
```copy
Install and setup instructions: https://github.com/projectdiscovery/httpx
```
Python Dependencies
This project uses the following Python libraries. You can install them with pip:

```copy
pip install -r requirements.txt
```

Alternatively, install them manually:
```copy
pip install requests beautifulsoup4 rich
```
Usage
Clone the repository or download the project files.
Make sure all required external tools are installed and accessible in your system's PATH.
Prepare a resolver list file at resolver/resolvers.txt (you can find public resolvers lists online).
Run the main script:

```copy
python3 main.py
```
Follow the on-screen prompts to enter domain(s), choose output format, and optionally run further DNS and HTTP checks.

Note: This tool requires active internet connection and proper permissions to execute external commands.
