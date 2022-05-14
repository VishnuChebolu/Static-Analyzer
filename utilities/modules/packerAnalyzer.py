import yara
import os
from rich import table

path = os.getcwd()

def rule_based_yara(target_file):
    rules = os.listdir(path+"Systems/Multiple/Packer_Rules")
    yara_matches = []
    for rule in rules:
        try:
            rule_obj = yara.compile(f"{path}/Systems/Multiple/Packer_Rules/{rule}")  
            tempmatch = rule_obj.match(target_file)
            if tempmatch != []:
                for matched in tempmatch:
                    if matched.strings != []:
                        yara_matches.append(matched)
        except Exception:
            continue
    if yara_matches != []:
        for rul in yara_matches:
            yara_table = Table()
            print(f">>> Rule name: [i][bold magenta]{rul}[/i]")
            yara_table.add_column("[bold green]Offset", justify="center")
            yara_table.add_column("[bold green]Matched String/Byte", justify="center")
            for mm in rul.strings:
                yara_table.add_row(f"{hex(mm[0])}", f"{str(mm[2])}")
            print(yara_table)
            print(" ")
    else:
        print(f"[bold white on red]Not any rules matched for {target_file}")