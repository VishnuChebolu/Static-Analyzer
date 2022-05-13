import pyfiglet
import sys
import os
sys.path.append(os.getcwd()+"/utilities")
from utilities.logging.log import Log
print(pyfiglet.figlet_format('Static Analyzer'))
Log.success("\t\t\t  All in one static malware analysis tool")
Log.info("\t\t\t\t\t\tby Vishnu Chebolu")