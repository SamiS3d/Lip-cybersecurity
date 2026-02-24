from colorama import init, Fore, Style

init(autoreset=True)

class Colors:
    INFO = f"{Fore.CYAN}[*]{Style.RESET_ALL}"
    SUCCESS = f"{Fore.GREEN}[+]{Style.RESET_ALL}"
    WARNING = f"{Fore.YELLOW}[!]{Style.RESET_ALL}"
    ERROR = f"{Fore.RED}[-]{Style.RESET_ALL}"
    FINDING = f"{Fore.MAGENTA}{Style.BRIGHT}[FINDING]{Style.RESET_ALL}"
    RESET = Style.RESET_ALL