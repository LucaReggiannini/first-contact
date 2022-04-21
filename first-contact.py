# first-contact Copyright 2017, 2022 Luca Reggiannini
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import subprocess
import sys
import io
from pathlib import Path # Used to convert strings to paths, get filenames from paths and check if files exists
import tempfile # Get temporary directory (cross-platform)
import os # Used to join paths (cross-platform) and list files through directories
import re
import shutil # Used to extract archives and delete files
import argparse 
import magic # Used to detect mime types from file content

def __getMime(path):
	mime = magic.Magic(mime=True)
	return mime.from_file(path)

def __getTmp():
	# Get temporary directory (cross-platform)
	return tempfile.gettempdir()

def __execute(program):
	# This function will:
	# 1. execute a program
	# 2. wait for the program to complete
	# 3. print output to stdout
	process = subprocess.Popen(
		program, 
		stdout=subprocess.PIPE
		)
	stdout = process.communicate()[0]
	return stdout.decode('ascii', 'replace')

def __verbose(text):
	if verbose == True:
		print("Verbose: " + text)
def __warning(text):
	print("Warning: " + text)
def __info(text):
	print("Info: " + text)
def __error(text):
	print("Error: " + text, file = sys.stderr)

def __help():
	print("""
first-contact

SYNOPSIS
	first-contact [OPTION] FILE

DESCRIPTION
	Shows evidence of possible malware infection within some file types

	Tests for MS Office files:
	1. Macro detection (via oledump, olefile)
	2. URLs and IPv4 detection

	Tests for PDF files:
	1. JavaScript and Action tags (via pdf-parser)
	2. JBIG2, Flash and XFA forms (via pdf-parser)
	3. URLs and IPv4 detection

	Tests for every other file type:
	1. URLs and IPv4 detection

URLS DETECTION
	Extracts URLs from a file using a regular expression.
	This Regex is based on a superficial interpretation of RFC1738 (see: https://datatracker.ietf.org/doc/html/rfc1738) so it may not work on all types of data.
	Use this script at your own risk and verify if the matches are correct!

	Matches <scheme>://<scheme-specific-part> (two slashes have been added to the RFC definition).
	Scheme names consist of letters "a"--"z" (not case sensitive), digits, and the following characters "+", ".", "-".
	Scheme specific part can be everything until a non safe character (defined in RFC) is matched: "<", ">", "{", "}", "|", "\", "^", "[", "]", "`".
	Omitted safe character are: "%", "#" and "~". They can be used to obfuscate malicious payloads into working URLs.

	If you want some specific results to be excluded from the match, insert them in the "whitelist.cfg" file (one per line).
	For example, put "raw.githubusercontent.com" to excluded it from URL pattern match.

	Note: this detection process is simply based on a regular expression so, ofcourse, it will NOT detect splitted URLs (for example an URL splitted in various Sheets and "re-assembled" runtime by an Excel 4.0 Macro).

IPV4 DETECTION
	Extracts IPv4 from a file using a regular expression.
	This Regex matches 4 groups of numbers consisting of three digits and separated by a period.

	Note: this will also match invalid IPv4 like 999.123.120.288

OPTIONS
	-h, --help 
		show this manual

	-v, --verbose 
		show more informations during execution

	-p, --preserve-after-extraction
		Do not delete extracted archives content after analysis.
		Archive content is extracted in $tmp/first-contact/$archive-name

	""")
	sys.exit()

verbose = False
preserveAfterExtraction = 0

FOLDER_DEPENDENCIES = os.path.join(os.path.dirname(__file__), "dependencies") # Used to store needed components
FOLDER_TEMP = os.path.join(__getTmp(), "first-contact") # used to store temp files
FILE_DEPENDENCIES_OLEDUMP = os.path.join(FOLDER_DEPENDENCIES, "oledump.py")
FILE_DEPENDENCIES_PDF_PARSER = os.path.join(FOLDER_DEPENDENCIES, "pdf-parser.py")
FILE_REGEX_IOC_EXCLUSIONS = os.path.join(os.path.dirname(__file__), "whitelist.cfg")
REGEX_URLS = "([a-zA-Z0-9\+\.\-]+:\/\/.*?)[\<|\>|\"|\{|\}|\||\\|\^|\[|\]|\`|\s|\n]"
REGEX_IPV4 = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
REGEX_IOC_EXCLUSIONS = []

# Load your whitelisted URLs and IPv4s from "whitelist.cfg"
with open(FILE_REGEX_IOC_EXCLUSIONS) as file:
	for line in file:
		REGEX_IOC_EXCLUSIONS.append(line.rstrip())

def __test_MSO_macro(path):
	o = __execute(["python3", FILE_DEPENDENCIES_OLEDUMP, path])
	if re.search(" M | O | E | \! ", o): # 'm' omitted to prevent false positives
		__warning("Macro detected")

def __test_PDF_objects(path):
	o = __execute(["python3", FILE_DEPENDENCIES_PDF_PARSER, "--stats", path])
	if re.search("/JS|/JavaScript|/AA|/OpenAction|/Launch", o):
		__warning("Active content detected")
	if re.search("/JBIG2Decode|/RichMedia|/XFA", o):
		__info("Interesting content detected")

def __test_ALL_URLS(path):
	__test_ALL_pattern(path, REGEX_URLS, REGEX_IOC_EXCLUSIONS, "URL")
def __test_ALL_IPV4(path):
	__test_ALL_pattern(path, REGEX_IPV4, REGEX_IOC_EXCLUSIONS, "IPv4")
def __test_ALL_pattern(path, pattern, whitelist, label):
	stream = io.open(
	path,
	mode = "r",	
	encoding = "utf-8",
	errors = "surrogateescape")

	fileContent = stream.read()

	matches = re.findall(pattern, fileContent)
	matches = list(dict.fromkeys(matches)) # Remove duplicates

	foundElements = []

	if matches:
		for match in matches:
			for exclusion in whitelist:
				if exclusion in match:
					break
			else:
				foundElements.append(match) 

	foundElements = list(dict.fromkeys(foundElements)) # Remove duplicates

	if foundElements:
		if verbose == False:
			__info(label + " scheme detected in " + path)
		else:
			for foundElement in foundElements:
				__verbose("Pattern " + label + " found (" + foundElement + ") in " + str(path))
			
			

def __test_ARCHIVE(path):
	# Extract the archive
	# /$tmp/first-contact/$archive-name
	extractionDirectory = os.path.join(FOLDER_TEMP, Path(path).stem)
	__info("Extracting as archive into " + str(extractionDirectory))
	try:
		shutil.unpack_archive(path, extractionDirectory)
	except: # If can not detect archive format, try ZIP
		try:
			shutil.unpack_archive(path, extractionDirectory, "zip")
		except:
			__error("Can not extract as archive.")
			return

	# Get file list from directory recursively
	filesList = []
	for root, dirs, files in os.walk(extractionDirectory):
		for file in files:
			filePath = os.path.join(root, file)
			__test_ALL_URLS(filePath)
			__test_ALL_IPV4(filePath)

	# Remove extracted files
	if preserveAfterExtraction == 0:
		shutil.rmtree(extractionDirectory)

def __main():
	if len(sys.argv) == 1:
		__error("No arguments given")
		__help()
	
	# Parse arguments bu shift
	args = sys.argv[1:]
	while len(args):
		if args[0] == "-h" or args[0] == "--help":
			__help()
		elif args[0] == "-v" or args[0] == "--verbose":
			global verbose 
			verbose = True
			__verbose("Output is verbose")
		elif args[0] == "-p" or args[0] == "--preserve-after-extraction":
			preserveAfterExtraction = 1
		else:
			file = args[0]
		args = args[1:] # shift

	# Check if file parameter is populated
	try:
		file = Path(file)
	except:
		__error("Invalid file given")
		exit()

	# Check if file exists
	if not Path(file).is_file():
		__error("Invalid file given")
		exit()

	mime = __getMime(file)
	__verbose("MIME " + mime)

	if re.search("Microsoft|Word|Excel", mime, re.IGNORECASE):
		__info("MS Office file detected")
		__test_MSO_macro(file)
		__test_ALL_URLS(file)
		__test_ALL_IPV4(file)
		__test_ARCHIVE(file)
	elif re.search("PDF", mime, re.IGNORECASE):
		__info("Portable Document Format file detected")
		__test_PDF_objects(file)
		__test_ALL_URLS(file)
		__test_ALL_IPV4(file)
	else:
		__info("Unknow file type")
		__test_ALL_URLS(file)
		__test_ALL_IPV4(file)

	__info("Analysis complete.")
if __name__ == "__main__":
	__main()