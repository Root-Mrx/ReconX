import subprocess,readline,os,logging,sys,json,requests,re,time,random,string,shutil
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
CLEANED_FILE = os.path.join(RESULTS_DIR, "cleaned_subs.txt")
ALIVE_FILE = os.path.join(RESULTS_DIR, "alive_subs.txt")
WILDCARD_TEST_FILE = os.path.join(RESULTS_DIR, "wildcard_test.txt")
WILDCARD_HITS_FILE = os.path.join(RESULTS_DIR, "wildcard_hits.txt")
DNSGEN_PERMUTATIONS_FILE = os.path.join(RESULTS_DIR, "dnsgen_permutations.txt")
DNSGEN_FILTERED_FILE = os.path.join(RESULTS_DIR, "dnsgen_filtered.txt")
RESOLVERS_FILE = "resolver/resolvers.txt"

# --- اطمینان از فولدرها ---
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

# --- تنظیمات لاگینگ ---
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
        for p in range(2, max_page+1):
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

def clean_subdomains_file():
    if not os.path.isfile(SUBDOMAINS_FILE):
        print(f"{RED}[!]{RESET} {SUBDOMAINS_FILE} not found!")
        logging.error(f"{SUBDOMAINS_FILE} not found")
        return False

    if os.path.isfile(CLEANED_FILE):
        os.remove(CLEANED_FILE)

    cmd = (
        f"cat {SUBDOMAINS_FILE} | "
        "sed -E 's/:[0-9]+$//' | "
        "grep -Eo '([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})' | "
        f"sort -u > {CLEANED_FILE}"
    )
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=60)
        logging.info(f"Cleaned subs saved to {CLEANED_FILE}")
        return True
    except Exception as e:
        logging.error(f"clean_subdomains_file error: {e}")
        return False

def append_wordlist_to_domains(wordlist_path, main_domains):
    if not os.path.isfile(wordlist_path):
        print(f"{RED}[!]{RESET} Wordlist '{wordlist_path}' not found!")
        logging.error(f"Wordlist {wordlist_path} not found")
        return False
    if not os.path.isfile(CLEANED_FILE):
        print(f"{RED}[!]{RESET} Cleaned file {CLEANED_FILE} not found!")
        return False
    with open(wordlist_path, "r") as wf:
        words = [w.strip() for w in wf if w.strip()]
    # فقط به دامنه های اصلی وردلیست می چسبانیم
    new_subs = []
    for domain in main_domains:
        for w in words:
            new_subs.append(f"{w}.{domain}")
    with open(CLEANED_FILE, "a") as f:
        for s in new_subs:
            f.write(s + "\n")
    # مرتب‌سازی و حذف تکراری
    tmp_file = CLEANED_FILE + ".sorted"
    subprocess.run(f"sort -u {CLEANED_FILE} > {tmp_file}", shell=True, check=True, timeout=120)
    shutil.move(tmp_file, CLEANED_FILE)
    logging.info(f"Appended wordlist to {CLEANED_FILE}")
    return True

def run_dnsx():
    if not os.path.isfile(RESOLVERS_FILE):
        print(f"{RED}[!]{RESET} {RESOLVERS_FILE} not found! Add resolvers.")
        logging.error(f"{RESOLVERS_FILE} missing")
        return False
    with open(RESOLVERS_FILE, "r") as f:
        resolvers = [r.strip() for r in f if r.strip()]
    if not resolvers:
        print(f"{RED}[!]{RESET} {RESOLVERS_FILE} is empty!")
        logging.error(f"{RESOLVERS_FILE} empty")
        return False
    if os.path.isfile(ALIVE_FILE):
        os.remove(ALIVE_FILE)
    threads = 50
    cmd = f"dnsx -silent -r {RESOLVERS_FILE} -a -t {threads} -l {CLEANED_FILE} -o {ALIVE_FILE}"
    logging.info(f"Running dnsx: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=600)
        logging.info(f"dnsx output saved to {ALIVE_FILE}")
        return True
    except subprocess.TimeoutExpired:
        logging.error("dnsx timed out")
        print(f"{RED}[!]{RESET} dnsx timed out!")
        return False
    except Exception as e:
        logging.error(f"dnsx error: {e}")
        print(f"{RED}[!]{RESET} dnsx error!")
        return False

def detect_and_remove_wildcards():
    if not os.path.isfile(ALIVE_FILE):
        print(f"{RED}[!]{RESET} {ALIVE_FILE} not found!")
        return False
    with open(ALIVE_FILE, "r") as f:
        alive_subs = [l.strip() for l in f if l.strip()]
    fake_subs = []
    for sub in alive_subs:
        parts = sub.split('.', 1)
        if len(parts) == 2:
            rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            fake_subs.append(f"{rand}.{parts[1]}")
    with open(WILDCARD_TEST_FILE, "w") as f:
        for fs in fake_subs:
            f.write(fs + "\n")
    cmd = f"dnsx -silent -r {RESOLVERS_FILE} -a -l {WILDCARD_TEST_FILE} -o {WILDCARD_HITS_FILE}"
    logging.info(f"Running dnsx for wildcard detection: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=300)
    except Exception as e:
        logging.error(f"Wildcard dnsx error: {e}")
        return False
    with open(WILDCARD_HITS_FILE, "r") as f:
        hits = set(l.strip() for l in f if l.strip())
    to_remove = set()
    for fake, real in zip(fake_subs, alive_subs):
        if fake in hits:
            to_remove.add(real)
    if not to_remove:
        print(f"{GREEN}[✓]{RESET} No wildcard DNS detected.")
        return True
    filtered = [s for s in alive_subs if s not in to_remove]
    with open(ALIVE_FILE, "w") as f:
        for s in filtered:
            f.write(s + "\n")
    print(f"{YELLOW}[~]{RESET} Removed {len(to_remove)} wildcard DNS entries.")
    logging.info(f"Wildcard removed: {len(to_remove)}")
    return True

def run_dnsgen_and_filter_with_dnsx():
    if not os.path.isfile(ALIVE_FILE):
        print(f"{RED}[!]{RESET} {ALIVE_FILE} not found!")
        return False
    try:
        cmd_dnsgen = f"dnsgen {ALIVE_FILE} -o {DNSGEN_PERMUTATIONS_FILE}"
        logging.info(f"Running dnsgen: {cmd_dnsgen}")
        subprocess.run(cmd_dnsgen, shell=True, check=True, timeout=180)
        cmd_dnsx = f"dnsx -r {RESOLVERS_FILE} -a -l {DNSGEN_PERMUTATIONS_FILE} -o {DNSGEN_FILTERED_FILE}"
        logging.info(f"Running dnsx on dnsgen output: {cmd_dnsx}")
        subprocess.run(cmd_dnsx, shell=True, check=True, timeout=300)
        with open(DNSGEN_FILTERED_FILE, "r") as f:
            filtered_subs = set(l.strip() for l in f if l.strip())
        with open(ALIVE_FILE, "r") as f:
            alive_subs = set(l.strip() for l in f if l.strip())
        new_subs = filtered_subs - alive_subs
        if not new_subs:
            print(f"{YELLOW}[~]{RESET} No new live subdomains after dnsgen + dnsx.")
            return True
        with open(ALIVE_FILE, "a") as f:
            for s in sorted(new_subs):
                f.write(s + "\n")
        print(f"{GREEN}[✓]{RESET} Added {len(new_subs)} new live subdomains after dnsgen + dnsx.")
        logging.info(f"Added {len(new_subs)} new subs after dnsgen + dnsx")
        return True
    except Exception as e:
        logging.error(f"dnsgen + dnsx phase error: {e}")
        print(f"{RED}[!]{RESET} Error in dnsgen + dnsx phase")
        return False

def path_completer(text, state):
    if '~' in text:
        text = os.path.expanduser(text)
    if not text.startswith('/'):
        text = os.path.join(os.getcwd(), text)
    dirname = os.path.dirname(text)
    basename = os.path.basename(text)
    try:
        entries = os.listdir(dirname or '.')
    except FileNotFoundError:
        return None
    matches = [os.path.join(dirname, e) for e in entries if e.startswith(basename)]
    matches = sorted(matches)
    try:
        return matches[state]
    except IndexError:
        return None

def input_with_completion(prompt=""):
    readline.set_completer(path_completer)
    readline.parse_and_bind("tab: complete")
    try:
        return input(prompt)
    finally:
        readline.set_completer(None)

def run_tool(tool_cmd, tool_name, progress, task_id):
    output = run_command(tool_cmd)
    progress.update(task_id, description=f"{tool_name} ✓")
    return output

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

    # پاکسازی فولدر results
    for f in os.listdir(RESULTS_DIR):
        os.remove(os.path.join(RESULTS_DIR, f))

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

    output_format = input(f"{YELLOW}[*]{RESET} Output format? (txt/json): ").strip().lower()
    if output_format not in ["json", "txt", ""]:
        print(f"{RED}[!]{RESET} Invalid format. Exiting.")
        sys.exit(1)

    start_time = datetime.now()
    all_results = []

    with Progress("[progress.description]{task.description}", BarColumn()) as progress:
        with ThreadPoolExecutor(max_workers=5) as executor:
            tasks = {
                "Subfinder": lambda d: f"subfinder -d {d} -all -silent | sort -u",
                "Assetfinder": lambda d: f"assetfinder -subs-only {d} | sort -u",
                "AbuseIPDB": lambda d: (f"curl -s https://www.abuseipdb.com/whois/{d} | "
                                        "grep \"<li>\\w.*</li>\" | sed -E 's/<\\/?li>//g' | sort -u"),
            }
            for domain in domains:
                print(f"\n{YELLOW}[*]{RESET} Processing domain: {domain}")
                futures = {}
                progress_tasks = {}
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
                progress.add_task("RapidDNS ✓", total=1, completed=1)
                all_results.extend(rapiddns_subs)

                crtsh_subs = get_crtsh_subdomains(domain)
                progress.add_task("crt.sh ✓", total=1, completed=1)
                all_results.extend(crtsh_subs)

                wayback_out = run_command(
                    f"curl -s \"https://web.archive.org/cdx/search/cdx?url=*.{domain}&collapse=urlkey&fl=original\" | cut -d '/' -f3 | sort -u",
                    timeout=120
                )
                progress.add_task("Wayback ✓", total=1, completed=1)
                all_results.extend(wayback_out.splitlines())

                time.sleep(1)

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

    run_phase2 = input(f"\n{YELLOW}[*]{RESET} Run dnsx/httpx on results? [y/n]: ").strip().lower()
    if run_phase2 == "y":
        wordlist_path = input_with_completion(f"{YELLOW}[*]{RESET} Enter full path to wordlist (or leave empty to skip): ").strip()
        phase_two(wordlist_path if wordlist_path else None, domains)
    else:
        print(f"{YELLOW}[~]{RESET} Skipping phase 2.")


phase_two_ran = False
def phase_two(wordlist_path=None, main_domains=None):
    logging.info("Phase 2 started")
    print(f"\n{CYAN}[~]{RESET} Phase 2: Cleaning, appending wordlist, running dnsx, wildcard detection, dnsgen...\n")

    with Progress("[progress.description]{task.description}", BarColumn()) as progress:
        task_clean = progress.add_task(f"{YELLOW}Cleaning subdomains...{RESET}", total=None)
        if not clean_subdomains_file():
            print(f"{RED}[!]{RESET} Cleaning failed. Exiting phase 2.")
            return
        progress.update(task_clean, description=f"{GREEN}Cleaned ✓{RESET}")

        if wordlist_path and main_domains:
            task_append = progress.add_task(f"{CYAN}Appending wordlist...{RESET}", total=None)
            if not append_wordlist_to_domains(wordlist_path, main_domains):
                print(f"{RED}[!]{RESET} Append wordlist failed. Exiting phase 2.")
                return
            progress.update(task_append, description=f"{GREEN}Wordlist appended ✓{RESET}")

        task_dnsx = progress.add_task(f"{CYAN}Running dnsx...{RESET}", total=None)
        if not run_dnsx():
            print(f"{RED}[!]{RESET} dnsx failed. Exiting phase 2.")
            return
        detect_and_remove_wildcards()
        progress.update(task_dnsx, description=f"{GREEN}dnsx done ✓{RESET}")

        task_dnsgen = progress.add_task(f"{CYAN}Running dnsgen + dnsx filter...{RESET}", total=None)
        run_dnsgen_and_filter_with_dnsx()
        progress.update(task_dnsgen, description=f"{GREEN}dnsgen done ✓{RESET}")

    print(f"\n{GREEN}[✓]{RESET} Phase 2 complete!")

if __name__ == "__main__":
    main()
