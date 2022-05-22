import os
import sys
from log import Log

try:
    from rich import print
    from rich.table import Table
except:
    Log.error("rich module not found.")
    sys.exit(1)

try:
    import yara
except:
    Log.error("yara module not found.")
    sys.exit(1)


try:
    from tqdm import tqdm
except:
    Log.error("tqdm not found.")
    sys.exit(1)


sc0pe_path = '/home/kali/Desktop/vishnu/static_analyzer/Static-Analyzer/'
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
targetFile = str(sys.argv[1])


file_sigs = {'UPX': 'UPX0', 'AsPack': '.aspack', 'ConfuserEx v0.6.0': 'ConfuserEx v0.6.0',
             'UPX!': 'UPX!', 'Confuser v1.9.0.0': 'Confuser v1.9.0.0', 'PEtite': 'petite',
             'MEW': 'MEW', 'MPRESS_1': 'MPRESS1', 'MPRESS_2': 'MPRESS2H'}


def YaraBased(target_file):
    yara_match_indicator = 0
    allRules = os.listdir(f"{sc0pe_path}/Systems/Multiple/Packer_Rules/")
    yara_matches = []
    for rul in allRules:
        try:
            rules = yara.compile(
                f"{sc0pe_path}/Systems/Multiple/Packer_Rules/{rul}")
            tempmatch = rules.match(target_file)
            if tempmatch != []:
                for matched in tempmatch:
                    if matched.strings != []:
                        yara_matches.append(matched)
        except:
            continue

    if yara_matches != []:
        yara_match_indicator += 1
        for rul in yara_matches:
            yaraTable = Table()
            print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
            yaraTable.add_column("[bold green]Offset", justify="center")
            yaraTable.add_column(
                "[bold green]Matched String/Byte", justify="center")
            for mm in rul.strings:
                yaraTable.add_row(f"{hex(mm[0])}", f"{str(mm[2])}")
            print(yaraTable)
            print(" ")

    if yara_match_indicator == 0:
        print(f"[bold white on red]Not any rules matched for {target_file}")


def Analyzer():
    try:
        if os.path.isfile(targetFile) == True:
            data = open(targetFile, "rb").read()
        else:
            pass
    except:
        print("[bold white on red]An error occured while opening the file.")
        sys.exit(1)

    packTable = Table()
    packTable.add_column("[bold green]Extracted Strings", justify="center")
    packTable.add_column("[bold green]Packer Type", justify="center")

    packed = 0
    print("[bold magenta]>>>[white] Performing [bold green][blink]strings[/blink] [white]based scan...")
    for pack in file_sigs:
        if file_sigs[pack].encode() in data:
            packed += 1
            packTable.add_row(
                f"[bold red]{file_sigs[pack]}", f"[bold red]{pack}")

    if packed == 0:
        print("\n[bold white on red]Nothing found.\n")
    else:
        print(packTable)

    print("[bold magenta]>>>[white] Performing [bold green][blink]YARA Rule[/blink] [white]based scan...")
    YaraBased(target_file=targetFile)


def MultiAnalyzer():

    answers = Table()
    answers.add_column("[bold green]File Names", justify="center")
    answers.add_column("[bold green]Extracted Strings", justify="center")
    answers.add_column("[bold green]Packer Type", justify="center")

    if os.path.isdir(targetFile) == True:
        allFiles = os.listdir(targetFile)

        filNum = 0
        for _ in allFiles:
            filNum += 1

        multipack = 0
        print("[bold red]>>>[white] Static Analyzer scans everything under that folder for malicious things. [bold][blink]Please wait...[/blink]")
        for tf in tqdm(range(0, filNum), desc="Scanning..."):
            if allFiles[tf] != '':
                scanme = f"{targetFile}/{allFiles[tf]}"
                try:
                    if os.path.isfile(scanme) == True:
                        mulData = open(scanme, "rb").read()
                    else:
                        pass
                except:
                    Log.error("An error occured while opening the file.")
                    sys.exit(1)

                for pack in file_sigs:
                    if file_sigs[pack].encode() in mulData:
                        multipack += 1
                        answers.add_row(
                            f"[bold red]{allFiles[tf]}", f"[bold red]{file_sigs[pack]}", f"[bold red]{pack}")

        if multipack == 0:
            Log.error("Nothing found.\n")
        else:
            print(answers)
            print(" ")


if __name__ == '__main__':
    if str(sys.argv[2]) == '--single':
        try:
            Analyzer()
        except:
            Log.error("Program terminated!\n")

    elif str(sys.argv[2]) == '--multiscan':
        try:
            MultiAnalyzer()
        except:
            Log.error("Program terminated!\n")

    else:
        pass


# python3 packerAnalyzer.py warp_test.exe --single   