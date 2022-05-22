#!/usr/bin/python3

import os
import sys

from log import Log

try:
    import exiftool
except:
    Log.error("PyExifTool module not found.")
    sys.exit(1)

try:
    from rich import print
except:
    Log.error("rich module not found.")
    sys.exit(1)


infoS = f"[bold cyan][[bold red]*[bold cyan]][white]"

def GetExif(mfile):
    print(f"{infoS} Extracting metadata from target file...\n")

    with exiftool.ExifTool() as et:
        mdata = et.get_metadata(mfile)

    print(f"{infoS} Exif/Metadata information")
    for md in mdata:
        try:
            if "ExifTool" in md or "Error" in md:
                pass
            else:
                print(f"[magenta]>>>[white] {md.split(':')[1]}: [green][i]{mdata[md]}[/i]")
        except:
            continue

mfile = sys.argv[1]
if os.path.isfile(mfile):
    GetExif(mfile)
else:
    Log.error("Target file not found!")