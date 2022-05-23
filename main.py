#!/usr/bin/python3
from utilities.modules.log import Log
import pyfiglet

print(pyfiglet.figlet_format('Static Analyzer'))
print('\t\t\t\t\t\tBy VishnuChebolu')

from dotenv import load_dotenv
load_dotenv()
import os
API = os.getenv("VTAPI")

try:
    import sys
    import argparse
    import configparser
except:
    Log.error("Missing modules detected!")
    sys.exit(1)

try:
    from rich import print
    from rich.table import Table
except:
    Log.error("rich module not found.")
    sys.exit(1)

#
try:
    from colorama import Fore, Style
except:
    Log.error("colorama module not found.")
    sys.exit(1)


# Colors
red = Fore.LIGHTRED_EX
cyan = Fore.LIGHTCYAN_EX
white = Style.RESET_ALL
green = Fore.LIGHTGREEN_EX

infoC = f"{cyan}[{red}*{cyan}]{white}"
infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"
foundS = f"[bold cyan][[bold red]+[bold cyan]][white]"
errorS = f"[bold cyan][[bold red]![bold cyan]][white]"




sc0pe_path = '/home/kali/Desktop/vishnu/static_analyzer/Static-Analyzer/utilities'

args = []
parser = argparse.ArgumentParser()

parser.add_argument("--all", required=False,
                    help="Extract information from all the methods.",
                    action="store_true")

parser.add_argument("--file", required=False,
                    help="Specify a file to scan or analyze.")
                    
parser.add_argument("--folder", required=False,
                    help="Specify a folder to scan or analyze.")

parser.add_argument("--domain", required=False,
                    help="Extract URLs and IP addresses from file.",
                    action="store_true")

parser.add_argument("--hashscan", required=False,
                    help="Scan target file's hash in local database.",
                    action="store_true")

parser.add_argument("--metadata", required=False,
                    help="Get exif/metadata information.",
                    action="store_true")

parser.add_argument('--pestudio', required=False,
                    help='Check information of the sample using PeStudio tool.',
                    action='store_true')

parser.add_argument("--packer", required=False,
                    help="Check if your file is packed with common packers.",
                    action="store_true")
                    
parser.add_argument("--sigcheck", required=False,
                    help="Scan file signatures in target file.", action="store_true")
                    
parser.add_argument("--vtFile", required=False,
                    help="Scan your file with VirusTotal API.",
                    action="store_true")
args = parser.parse_args()


def hashdb():
    Log.info("Scanning Hash in Database...")
    # argv[1] = file/folder
    # argv[2] = --normal/--multiscan

    if args.file is not None:
        command = f"python3 {sc0pe_path}/modules/hashScanner.py {args.file} --normal"
        os.system(command)

    if args.folder is not None:
        command = f"python3 {sc0pe_path}/modules/hashScanner.py {args.folder} --multiscan"
        os.system(command)

def sigcheck():
    Log.info("Scanning File Signature...")

    if args.file is not None:
        command = f"python3 {sc0pe_path}/modules/sigChecker.py {args.file}"
        os.system(command)
    
    if args.folder is not None:
        Log.error("--sigcheck argument is not supported for folder analyzing!\n")
        sys.exit(1)


def metadata():
    Log.info("Scanning metadata of the sample...")
    if args.file is not None:
        command = f"python3 {sc0pe_path}/modules/metadata.py {args.file}"
        os.system(command)
    
    if args.folder is not None:
        Log.error("--metadata argument is not supported for folder analyzing!\n")
        sys.exit(1)

def vtfile():
    Log.info('Scanning using Virus Total API...')
    if args.file is not None:            
        if API == '' or API is None or len(API) != 64:
            print("[bold]Please get your API key from -> [bold green][a]https://www.virustotal.com/[/a] and enter it in .env file\n")
            sys.exit(1)
        else:
            command = f"python3 {sc0pe_path}/modules/VTwrapper.py {API} {args.file}"
            os.system(command)
    
    if args.folder is not None:
        Log.error("If you want to get banned from VirusTotal then do that :).\n")
        sys.exit(1)

def pe():
    Log.info('Scanning using PEStudio API...')
    if args.file is not None:
        command = f"python3 {sc0pe_path}/modules/packerAnalyzer.py {args.file} --single"
        os.system(command)
    
    if args.folder is not None:
        command = f"python3 {sc0pe_path}/modules/packerAnalyzer.py {args.folder} --multiscan"
        os.system(command)

def domain():
    Log.info('Scanning using Regex...')
    if args.file is not None:
        command = f"python3 {sc0pe_path}/modules/domainCatcher.py"
        os.system(command)
    
    if args.folder is not None:
        Log.error("--domain argument is not supported for folder analyzing!\n")
        sys.exit(1)

def packerIdentify():
    Log.info('Scanning using PEID tool...')
    if args.file is not None:
        command = f"python3 {sc0pe_path}/modules/packerIdentifier.py {args.file}"
        os.system(command)
    
    if args.folder is not None:
        Log.error("--packer argument is not supported for folder analyzing!\n")
        sys.exit(1)

def static_analyzer():
    if args.all:
        Log.info('Performing all the available scans.')
        
        try:
            hashdb()
            pass
        except:
            pass
        
        try:
            sigcheck()
            pass
        except:
            pass
        
        try:
            metadata()
            pass
        except:
            pass
        
        try:
            vtfile()
            pass
        except:
            pass
        
        try:
            pe()
            pass
        except:
            pass
        
        try:
            domain()
            pass
        except:
            pass
        
        try:
            packerIdentify()
            pass
        except:
            pass

    # Hash Scanning
    if args.hashscan:        
        hashdb()

    # File signature scanner
    if args.sigcheck:
        sigcheck()

    # metadata
    if args.metadata:
        metadata()


    # VT File scanner
    if args.vtFile:
        vtfile()

    # pestudio
    if args.pestudio:
        pe()

    # domain extraction
    if args.domain:
        domain()

    # packer identifier
    if args.packer:
        packerIdentify()

static_analyzer()