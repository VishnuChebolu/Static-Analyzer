import peid
import sys
import os

from sympy import EX
from log import Log

try:
    from rich import print
    from rich.table import Table
except:
    Log.error("rich module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    Log.error("colorama module not found.")
    sys.exit(1)

# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL

# Legends
infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

if os.path.exists(sys.argv[1]):
    try:
        var = peid.identify_packer(sys.argv[1])
        Log.query("Packer Identified.")
        print(f"[bold magenta]>>>[white] Packer Type :: [bold yellow]{var[0][1][0]}")
    except Exception as e:
        Log.error(str(e)[1:-1])
else:
    Log.error('File not found!')
