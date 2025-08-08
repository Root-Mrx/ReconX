import subprocess, readline, os, logging, sys, json, requests, re, time
from datetime import datetime
from bs4 import BeautifulSoup
from rich.progress import Progress, BarColumn
from concurrent.futures import ThreadPoolExecutor

CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"
RESET = "\033[0m"

LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "reconx.log")
RESULTS_DIR = "results"
SUBDOMAINS_FILE = os.path.join(RESULTS_DIR, "subdomains.txt")

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def run_command(cmd, timeout=300):
    logging.info(f"Executing: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
        if result.returncode != 0:
            logging.warning(f"Command failed ({result.returncode}): {cmd}\nStderr: {result.stderr.strip()}")
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout expired for command: {cmd}")
        return ""
    except Exception as e:
        logging.error(f"Error running command {cmd}: {e}")
        return ""

def get_headers():
    return {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/115.0.0.0 Safari/537.36")
    }

def get_rapiddns_subdomains(domain):
    all_subs = set()
    base_url = f"https://rapiddns.io/s/{domain}?full=1&down=1"
    max_page = 1
    try:
        resp = requests.get(base_url, headers=get_headers(), timeout=60)
        logging.info(f"RapidDNS page 1 status: {resp.status_code}")
        if resp.status_code != 200:
            logging.warning(f"RapidDNS status code not 200: {resp.status_code}")
            return all_subs
        soup = BeautifulSoup(resp.text, "html.parser")
        tds = soup.find_all("td")
        for td in tds:
            txt = td.get_text(strip=True)
            if "." in txt:
                all_subs.add(txt)
        pages = soup.find_all("a", class_="page-link")
        for a in pages:
            href = a.get("href", "")
            m = re.search(r"page=(\d+)", href)
            if m:
                page_num = int(m.group(1))
                if page_num > max_page:
                    max_page = page_num
        for p in range(2, max_page + 1):
            url = f"{base_url}&page={p}"
            resp = requests.get(url, headers=get_headers(), timeout=60)
            logging.info(f"RapidDNS page {p} status: {resp.status_code}")
            if resp.status_code != 200:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            tds = soup.find_all("td")
            for td in tds:
                txt = td.get_text(strip=True)
                if "." in txt:
                    all_subs.add(txt)
    except Exception as e:
        logging.error(f"RapidDNS error: {e}")
    return all_subs

def get_crtsh_subdomains(domain):
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = requests.get(url, headers=get_headers(), timeout=60)
        if resp.status_code != 200:
            logging.warning(f"crt.sh status code {resp.status_code}")
            return subs
        data = resp.json()
        for entry in data:
            nv = entry.get("name_value", "")
            for line in nv.split("\n"):
                if "." in line:
                    subs.add(line.strip())
        logging.info(f"crt.sh found {len(subs)} subdomains")
    except Exception as e:
        logging.error(f"crt.sh error: {e}")
    return subs

def run_tool(tool_cmd, tool_name, progress, task_id):
    logging.info(f"Running tool {tool_name} with cmd: {tool_cmd}")
    output = run_command(tool_cmd)
    progress.update(task_id, description=f"{tool_name} ✓", completed=1)
    return output

def run_shosubgo(domains, api_key):
    if not api_key:
        print(f"{RED}[!]{RESET} Shodan API key is required for shosubgo!")
        return []

    temp_file = "temp_domains.txt"
    with open(temp_file, "w") as f:
        for d in domains:
            f.write(d + "\n")

    cmd = f"shosubgo -f {temp_file} -s {api_key} -json"
    output = run_command(cmd)
    os.remove(temp_file)

    if not output:
        print(f"{RED}[!]{RESET} shosubgo returned no output")
        return []

    try:
        data = json.loads(output)
        subs = []
        for entry in data:
            if 'subdomain' in entry:
                subs.append(entry['subdomain'])
        print(f"{GREEN}[✓]{RESET} shosubgo found {len(subs)} subdomains")
        return subs
    except Exception as e:
        logging.error(f"Error parsing shosubgo output: {e}")
        print(f"{RED}[!]{RESET} Failed to parse shosubgo output.")
        return []

def main():
    ascii_art = r"""
     _____                     __   __
    |  __ \                    \ \ / /
    | |__) |___  ___ ___  _ __  \ V / 
    |  _  // _ \/ __/ _ \| '_ \  > <  
    | | \ \  __/ (_| (_) | | | |/ . \ 
    |_|  \_\___|\___\___/|_| |_/_/ \_\
                      
                            1.2
    """
    print(ascii_art)
    print(f"{CYAN}[~]{RESET} Starting reconnaissance...\n")

    # پاکسازی نتایج قبلی
    for f in os.listdir(RESULTS_DIR):
        try:
            os.remove(os.path.join(RESULTS_DIR, f))
        except Exception as e:
            logging.error(f"Error removing file {f}: {e}")

    mode = input(f"{YELLOW}[*]{RESET} Enter mode ([s] for single domain, [m] for multiple domains): ").strip().lower()
    if mode == "s":
        domains = [input(f"{YELLOW}[*]{RESET} Enter domain: ").strip()]
    elif mode == "m":
        domains = []
        while True:
            d = input(f"{YELLOW}[*]{RESET} Enter domain (or empty to finish): ").strip()
            if not d:
                break
            domains.append(d)
    else:
        print(f"{RED}[!]{RESET} Invalid mode. Exiting.")
        sys.exit(1)

    api_key = input(f"{YELLOW}[*]{RESET} Enter your Shodan API key for shosubgo (or leave empty to skip): ").strip()

    output_format = input(f"{YELLOW}[*]{RESET} Output format? (txt/json): ").strip().lower()
    if output_format not in ["json", "txt", ""]:
        print(f"{RED}[!]{RESET} Invalid format. Exiting.")
        sys.exit(1)

    start_time = datetime.now()
    all_results = []

    with Progress("[progress.description]{task.description}", BarColumn()) as progress:
        with ThreadPoolExecutor(max_workers=5) as executor:
            for domain in domains:
                print(f"\n{YELLOW}[*]{RESET} Processing domain: {domain}")
                futures = {}
                progress_tasks = {}

                tasks = {
                    "Subfinder": lambda d: f"subfinder -d {d} -all -silent | sort -u",
                    "Assetfinder": lambda d: f"assetfinder -subs-only {d} | sort -u",
                    "AbuseIPDB": lambda d: (f"curl -s https://www.abuseipdb.com/whois/{d} | "
                                            "grep \"<li>\\w.*</li>\" | sed -E 's/<\\/?li>//g' | sort -u"),
                }

                for tool_name in tasks:
                    progress_tasks[tool_name] = progress.add_task(f"{tool_name}...", total=None)

                for tool_name, cmd_func in tasks.items():
                    cmd = cmd_func(domain)
                    futures[tool_name] = executor.submit(run_tool, cmd, tool_name, progress, progress_tasks[tool_name])

                for tool_name, future in futures.items():
                    try:
                        out = future.result()
                        if out:
                            all_results.extend(out.splitlines())
                    except Exception as e:
                        print(f"{RED}[!]{RESET} {tool_name} failed: {e}")

                rapiddns_subs = get_rapiddns_subdomains(domain)
                task_rapid = progress.add_task("RapidDNS...", total=1)
                progress.update(task_rapid, completed=1)
                all_results.extend(rapiddns_subs)

                crtsh_subs = get_crtsh_subdomains(domain)
                task_crtsh = progress.add_task("crt.sh...", total=1)
                progress.update(task_crtsh, completed=1)
                all_results.extend(crtsh_subs)

                wayback_out = run_command(
                    f"curl -s \"https://web.archive.org/cdx/search/cdx?url=*.{domain}&collapse=urlkey&fl=original\" | cut -d '/' -f3 | sort -u",
                    timeout=120
                )
                task_wayback = progress.add_task("Wayback...", total=1)
                progress.update(task_wayback, completed=1)
                all_results.extend(wayback_out.splitlines())

                time.sleep(1)

                if api_key:
                    print(f"{CYAN}[~]{RESET} Running shosubgo for {domain}...")
                    shosubgo_subs = run_shosubgo([domain], api_key)
                    all_results.extend(shosubgo_subs)

    unique_results = sorted(set(all_results))
    if output_format == "json":
        with open(os.path.join(RESULTS_DIR, "subdomains.json"), "w") as f:
            json.dump(unique_results, f, indent=2)
        print(f"\n{CYAN}[~]{RESET} Results saved to: {RESULTS_DIR}/subdomains.json")
    else:
        with open(SUBDOMAINS_FILE, "w") as f:
            for line in unique_results:
                f.write(line + "\n")
        print(f"\n{CYAN}[~]{RESET} Results saved to: {SUBDOMAINS_FILE}")

    end_time = datetime.now()
    print(f"{CYAN}[~]{RESET} Total reconnaissance time: {(end_time - start_time).total_seconds():.2f} seconds")

if __name__ == "__main__":
    print(f"{CYAN}[~]{RESET} Starting main execution")
    main()
    print(f"{CYAN}[~]{RESET} Finished main execution")
