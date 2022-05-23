#!/usr/bin/python3

import requests
import os
import re
import hashlib
import sys
import math
import json
from datetime import date

from log import Log


try:
    import sqlite3
except:
    Log.error("sqlite3 not found.")
    sys.exit(1)

try:
    from tqdm import tqdm
except:
    Log.error("tqdm not found.")
    sys.exit(1)

try:
    from rich import print
    from rich.table import Table
    from rich.live import Live
    from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
    from rich.layout import Layout
    from rich.text import Text
    from rich.panel import Panel
except:
    Log.error("rich module not found.")
    sys.exit(1)

try:
    from colorama import Fore, Style
except:
    Log.error("colorama module not found.")
    sys.exit(1)

today = date.today()
dformat = today.strftime("%d-%m-%Y")

# Colors
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

# Legends
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"


# Configurating installation directory
install_dir = '/home/kali/Desktop/vishnu/static_analyzer/Static-Analyzer/hashes'

def Downloader():
    local_database = f"{install_dir}/HashDB"
    dbUrl = "https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/HashDB"
    req = requests.get(dbUrl, stream=True)
    total_size = int(req.headers.get('content-length', 0))
    block_size = 1024
    wrote = 0
    print(f"\n{infoS} Downloading signature database please wait...")
    try:
        with open(local_database, 'wb') as ff:
            for data in tqdm(req.iter_content(block_size), total=math.ceil(total_size//block_size), unit='KB', unit_scale=True):
                wrote = wrote + len(data)
                ff.write(data)
        sys.exit(0)
    except:
        sys.exit(0)

def DatabaseCheck():
    if os.path.isfile(f"{install_dir}/HashDB") == False:
        Log.error('Local signature database not found!!')
        choose = str(input(f"{green}=>{white} Would you like to download it [Y/n]?: "))
        if choose == "Y" or choose == "y":
            Downloader()
        else:
            print("\n[bold white on red]Without local database [blink]--hashscan[/blink] [white]will not work!!\n")
            sys.exit(1)

# Hashing with md5
def GetHash(targetFile):
    hashMd5 = hashlib.md5()
    try:
        with open(targetFile, "rb") as ff:
            for chunk in iter(lambda: ff.read(4096), b""):
                hashMd5.update(chunk)
    except:
        pass
    return hashMd5.hexdigest()

# Accessing hash database content
if os.path.exists(f"{install_dir}/HashDB"):
    hashbase = sqlite3.connect(f"{install_dir}/HashDB")
    dbcursor = hashbase.cursor()
else:
    DatabaseCheck()

# Check for if database is up to date
def UpToDate():
    Log.info("Checking for database state...")
    try:
        dbs = requests.get("https://raw.githubusercontent.com/CYB3RMX/MalwareHashDB/main/README.md")
        database_content = dbcursor.execute(f"SELECT * FROM HashDB").fetchall()
        match = re.findall(str(len(database_content)), str(dbs.text))
        if match != []:
            print("[bold]Database State: [bold green]Up to date.\n")
        else:
            print("[bold]Database State: [bold red]Outdated.")
            print("[bold magenta]>>>[bold white] You should use [bold green]'--db_update' [bold white]argument to update your malware hash database.\n")
    except:
        print("[bold white on red]An error occured while connecting to Github!!")

# Updating database
def DatabaseUpdate():
    print("[bold magenta]>>>[bold white] Removing old database...")
    os.system(f"rm -rf {install_dir}/HashDB")
    Downloader()
    print("[bold green]>>>[bold white] New database has successfully downloaded.")

# Handling single scans
def NormalScan():
    # Hashing
    targetHash = GetHash(targetFile)
    # targetHash = '16a114b4f0e472487a3236d251672415b98d2324b3208af61b9b75c5e42e0d42'

    # Creating answer table
    answTable = Table()
    answTable.add_column("[bold green]Hash", justify="center")
    answTable.add_column("[bold green]Name", justify="center")

    # Total hashes
    database_content = dbcursor.execute(f"SELECT * FROM HashDB").fetchall()

    # Printing informations
    print(f"[bold cyan]>>>[white] Total Hashes: [bold green]{len(database_content)}")
    print(f"[bold cyan]>>>[white] File Name: [bold green]{targetFile}")
    print(f"[bold cyan]>>>[white] Target Hash: [bold green]{targetHash}\n")
    # Finding target hash in the database_content
    db_answer = dbcursor.execute(f"SELECT * FROM HashDB where hash=\"{targetHash}\"").fetchall()
    if db_answer != []:
        answTable.add_row(f"[bold red]{db_answer[0][0]}", f"[bold red]{db_answer[0][1]}")
        print(answTable)
    else:
        Log.error("Target hash is not in our database!!")
    hashbase.close()

username = 'vishnu'
# Handling multiple scans
def MultipleScan():
    # Scan report structure
    scan_report = {
        "report": [],
        "user": username,
        "date": dformat
    }

    # Creating application layout
    program_layout = Layout(name="RootLayout")
    program_layout.split_column(
        Layout(name="Top"),
        Layout(name="Bottom")
    )
    program_layout["Bottom"].split_row(
        Layout(name="bottom_left"),
        Layout(name="bottom_right")
    )
    program_layout["bottom_left"].split_column(
        Layout(name="bottom_left_upper"),
        Layout(name="bottom_left_lower")
    )
    program_layout["bottom_right"].split_column(
        Layout(name="bottom_right_upper"),
        Layout(name="bottom_right_lower")
    )

    # Handling folders
    if os.path.isdir(targetFile) == True:
        # Get all files under that directory recursively...
        print("[bold red]>>>[bold white] Qu1cksc0pe gathering all files under that directory recursively. [bold blink]Please wait...")
        scanfiles = Table()
        scanfiles.add_column("[bold green]Name", justify="center")
        scanfiles.add_column("[bold green]Count", justify="center")
        scan_count = 0
        file_names = []
        for root, d_names, f_names in os.walk(targetFile):
            for ff in f_names:
                file_names.append(os.path.join(root, ff))
                scan_count += 1
                if len(scanfiles.columns[0]._cells) < 13:
                    scanfiles.add_row(f"{os.path.join(root, ff)}", str(scan_count))
                else:
                    index = len(scanfiles.columns[0]._cells)
                    scanfiles.columns[0]._cells[index-1] = Text(f"{os.path.join(root, ff)}")
                    scanfiles.columns[1]._cells[index-1] = Text(str(scan_count))

        # Variables
        filNum = len(file_names)
        database_content = dbcursor.execute(f"SELECT * FROM HashDB").fetchall()

        # Creating summary table
        mulansTable = Table()
        mulansTable.add_column("[bold green]File Names", justify="center")
        mulansTable.add_column("[bold green]Hash", justify="center")
        mulansTable.add_column("[bold green]Name", justify="center")

        # Creating upper grid
        upper_grid = Table.grid()
        upper_grid.add_row(
            Panel(
                scanfiles, border_style="bold cyan", title="Files To Scan"
            ),
            Panel(
                mulansTable, border_style="bold red", title="Malicious Files"
            )
        )
        upper_panel = Panel(upper_grid, border_style="bold blue", title="Qu1cksc0pe Hashscan")
        program_layout["Top"].update(upper_panel)

        # Scan progress
        scan_progress = Progress(
            TextColumn("[bold]Scanning.."),
            BarColumn(),
            "[scan_progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn()
        )
        program_layout["bottom_left_upper"].update(Panel(scan_progress, border_style="bold green", title="Scan Progress", width=60, height=3))
        program_layout["bottom_left_lower"].update(
            Panel(
                Text(f"Date: {dformat}\nTarget Directory: {targetFile}\nDatabase Length: {len(database_content)}\nFiles To Scan: {scan_count}\nReport File: sc0pe_hashscan_report.json"), border_style="bold magenta",
                title="General Information" ,width=80, height=7
            )
        )
        program_layout["bottom_right_upper"].update(
            Panel(
                Text("Report status will appear if any malicious file found..."), 
                border_style="bold magenta", title="Scan Report Status", width=60, height=7
            )
        )
        program_layout["bottom_right_lower"].update(
            Panel(
                Text("Live scan status will appear when scan process start..."),
                border_style="bold cyan", title="Live Scan Status", width=90, height=10
            )
        )

        # Scan zone
        with Live(program_layout, refresh_per_second=1.1):
            for tf in scan_progress.track(range(0, filNum)):
                if file_names[tf] != '':
                    scanme = f"{file_names[tf]}"
                    targetHash = GetHash(scanme)
                    splitted = os.path.split(scanme)[1]

                    # Finding target hash in the database_content
                    db_answers = dbcursor.execute(f"SELECT * FROM HashDB where hash=\"{targetHash}\"").fetchall()
                    if db_answers != []:
                        if len(mulansTable.columns[0]._cells) < 11:
                            mulansTable.add_row(f"{splitted}", f"{db_answers[0][0]}", f"{db_answers[0][1]}")
                        else:
                            ans_ind = len(mulansTable.columns[0]._cells)
                            mulansTable.columns[0]._cells[ans_ind-1] = Text(f"{splitted}")
                            mulansTable.columns[1]._cells[ans_ind-1] = Text(f"{db_answers[0][0]}")
                            mulansTable.columns[2]._cells[ans_ind-1] = Text(f"{db_answers[0][1]}")
                        scan_report["report"].append(
                            {
                                "file_name": file_names[tf],
                                "file_hash": db_answers[0][0],
                                "threat_name": db_answers[0][1]
                            }
                        )
                        program_layout["bottom_right_upper"].update(
                            Panel(
                                Text(f"User: {username}\nDate: {dformat}\nMalicious File Count: {len(scan_report['report'])}"),
                                border_style="bold magenta", title="Scan Report Status", width=60, height=7
                            )
                        )
                    program_layout["bottom_right_lower"].update(
                        Panel(
                            Text(f"Current Directory: {os.path.split(scanme)[0]}\n\nCurrent File: {splitted}\n\nHash: {targetHash}"),
                            border_style="bold cyan", title="Live Scan Status", width=90, height=10
                        )
                    )
        hashbase.close()

    # Writing to report file
    with open("sc0pe_hashscan_report.json", "w") as rp_file:
        json.dump(scan_report, rp_file, indent=4)

if __name__ == '__main__':
    # File handling
    if str(sys.argv[1]) == '--db_update':
        DatabaseUpdate()
    else:
        targetFile = str(sys.argv[1])

    # Argument side
    if str(sys.argv[2]) == '--normal':
        UpToDate()
        NormalScan()
    elif str(sys.argv[2]) == '--multiscan':
        UpToDate()
        MultipleScan()
    else:
        pass


# python3 hashScanner.py warp_test.exe --normal
