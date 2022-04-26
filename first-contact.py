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
from   pathlib import Path # Used to convert strings to paths, get filenames from paths and check if files exists
import tempfile            # Get temporary directory (cross-platform)
import os                  # Used to join paths (cross-platform) and list files through directories
import re
import shutil              # Used to extract archives and delete files
import argparse
import magic               # Used to detect mime types from file content
import requests            # Used to perform HTTP requests
import json
import hashlib             # Used to calculate file hashes

def __getMime(path):
	mime = magic.Magic(mime=True)
	return mime.from_file(path)

def __getTmp():
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

def __loadList(file, list):
	# Populate a list with file lines
	with open(file) as f:
		for line in f:
			list.append(line.rstrip())

def __getFileContent(path):
	stream      = io.open(path,
	mode        = "r",	
	encoding    = "utf-8",
	errors      = "surrogateescape")
	fileContent = stream.read()

	return fileContent

def __alert(text):
	print("Alert       : " + text)
def __warning(text):
	print("Warning     : " + text)
def __info(text):
	print("Info        : " + text)
def __error(text):
	print("Error       : " + text, file = sys.stderr)
def __verbose(text):
	if verbose == True:
		print("Verbose     : " + text)
def __debug(text):
	if debug == True:
		print("Debug       : " + text)

def __help():
	print("""
first-contact

SYNOPSIS
	first-contact [OPTIONS...] [FILE]

DESCRIPTION
	Shows evidence of possible malware infection within some file types

	Tests for MS Office files:
	1. Macro detection (via oledump, olefile)
	2. URLs, IPv4 and Domains detection
	3. Blacklisted strings detection 
	4. Extraction as archive and perform generic tests for every files

	Tests for PDF files:
	1. JavaScript and Action tags (via pdf-parser)
	2. JBIG2, Flash and XFA forms (via pdf-parser)
	3. URLs, IPv4 and Domains detection
	4. Blacklisted strings detection 

	Generic tests (for every other file type):
	1. URLs, IPv4 and Domains detection
	2. Blacklisted strings detection 
	3. Extraction as archive and perform generic tests for every files

URLS DETECTION
	Extracts URLs from a file using a regular expression.
	This Regex is based on a superficial interpretation of RFC1738 (see: https://datatracker.ietf.org/doc/html/rfc1738) so it may not work on all types of data.

	Matches <scheme>://<scheme-specific-part> (two slashes have been added to the RFC definition).
	Scheme names consist of letters "a"--"z" (not case sensitive), digits, and the following characters "+", ".", "-".
	Scheme specific part can be everything until a non safe character (defined in RFC) is matched: "<", ">", "{", "}", "|", "\", "^", "[", "]", "`".
	Omitted safe character are: "%", "#" and "~". They can be used to obfuscate malicious payloads into working URLs.

	If you want some specific results to be excluded from the match, insert them in the "./cfg/whitelistUrls.cfg" file (one per line).
	For example, put "https://raw.githubusercontent.com" to excluded it from URL pattern match (every match that contains this string will be excluded!).

DOMAIN DETECTION
	Extract all domains from a file using a regular expression.
	This Regex in based on a superficial interpretation of RFC1034(see: https://www.ietf.org/rfc/rfc1034.txt, http://www.tcpipguide.com/free/t_DNSLabelsNamesandSyntaxRules.htm) so it may not work on all types of data.
	
	Matches <label-N>.<label>.<tld>.
	Labels consists of letters "a"--"z" (not case sensitive), digits, and the character "-"; maximum length is 63 chars.
	Labels are separated by the character "."
	The last label must be followed by the TLD.
	The TLD consists of letters "a"--"z" (not case sensitive), digits, and the character "-"; maximum length is 63 chars.
	Valid TLDs must be inserted in ./cfg/tlds.cfg (current list last updated on 26-04-2022).
	If a TLD is not in this config file the domain will not match (necessary to prevent most matches with filenames whose form is similar to that of a domain name).
	For a list of valid TLDs see https://www.iana.org/domains/root/db

	Since this pattern can easily match some filenames or strings contained in binary files, domain search is disabled by default to avoid false positives.
	Use option "-d" or "--domains" to enable this function.
	
	If you want some specific results to be excluded from the match, insert them in the "./cfg/whitelistDomains.cfg" file (one per line).
	For example, put "raw.githubusercontent.com" to excluded it from URL pattern match.

IPV4 DETECTION
	Extracts IPv4 from a file using a regular expression.
	This Regex matches 4 groups of numbers consisting of three digits and separated by a period.

	Note: this will also match invalid IPv4 like 999.123.120.288

	If you want some specific results to be excluded from the match, insert them in the "./cfg/whitelistIpv4.cfg" file (one per line).
	For example, put "127.0.0.1" to excluded it from IPv4 pattern match.

BLACKLISTED STRINGS
	Simply searches bad strings (case insensitive) previously entered in the "./cfg/blacklist.cfg" (one per line).

Note: every detections system based on strings or Regex will NOT detect splitted data (for example an URL splitted in various Sheets and "re-assembled" runtime by an Excel 4.0 Macro will not be detected).

OPTIONS
	-h, --help 
		show this manual

	-v, --verbose 
		show more informations during execution

	-d, --debug
		show debugging informations

	-c, --checksum
		Calculate file MD5, SHA1 and SHA256

	-D, --domains
		Enable Domains detection

	-f, --force-mime [MIME]
		Set file MIME manually (automatic MIME detection will be ignored)

	-k, --keep-after-extraction
		Do not delete extracted archives content after analysis.
		Archive content is extracted in $tmp/first-contact/$archive-name

	-V, --virustotal [API_KEY]
		Get VirusTotal report for given [FILE].
		If the file it is not submitted no data will not be uploaded
	
	-Vun, --virustotal-unlimited-names
		In the VirusTotal report shows all the names with which the file has been submitted or seen in the wild 
		If this option is not activated the limit is 10 names.

	""")
	sys.exit()

##########################################################################################

# GENERIC VARS AND CONST

verbose                      = False
debug                        = False
keepAfterExtraction          = False
printChecksum                = False
domainsDetection             = False
forceMime                    = False
forcedMime                   = ""

FOLDER_DEPENDENCIES          = os.path.join(os.path.dirname(__file__), "dependencies")                                                 # Used to store needed components
FOLDER_TEMP                  = os.path.join(__getTmp(), "first-contact")                                                               # used to store temp files

FILE_DEPENDENCIES_OLEDUMP    = os.path.join(FOLDER_DEPENDENCIES, "oledump.py")
FILE_DEPENDENCIES_PDF_PARSER = os.path.join(FOLDER_DEPENDENCIES, "pdf-parser.py")

FILE_WHITELIST_URLS          = os.path.join(os.path.dirname(__file__), "cfg", "whitelistUrls.cfg")
FILE_WHITELIST_IPV4          = os.path.join(os.path.dirname(__file__), "cfg", "whitelistIpv4.cfg")
FILE_WHITELIST_DOMAINS       = os.path.join(os.path.dirname(__file__), "cfg", "whitelistDomains.cfg")
FILE_BLACKLIST_STRINGS       = os.path.join(os.path.dirname(__file__), "cfg", "blacklist.cfg")
FILE_DOMAINS_TLDS            = os.path.join(os.path.dirname(__file__), "cfg", "tlds.cfg")

FILE_PYTHON                  = "python3"                                                                                               # Specify your Python executable (basename or path)

REGEX_URLS                   = "([a-zA-Z0-9\+\.\-]+:\/\/.*?)[\<|\>|\"|\{|\}|\||\\|\^|\[|\]|\`|\s|\n]"
REGEX_IPV4                   = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
REGEX_DOMAINS                = "((?:(?<!\w)[a-zA-Z0-9\-]{1,63}\.)*(?:(?<!\w)[a-zA-Z0-9\-]{1,63})(?:\.(?:[a-zA-Z0-9\-]{1,63})(?!\w)))"  # /http(?:s)?:\/\/(?:[\w-]+\.)*([\w-]{1,63})(?:\.(?:\w{3}|\w{2}))(?:$|\/)/i

WHITELIST_URLS          = []
WHITELIST_IPV4          = []
WHITELIST_DOMAINS       = []
BLACKLIST_STRINGS       = []
DOMAINS_TLDS            = []

# Populate lists with cfg files content

__loadList(FILE_WHITELIST_URLS,    WHITELIST_URLS)
__loadList(FILE_WHITELIST_IPV4,    WHITELIST_IPV4)
__loadList(FILE_WHITELIST_DOMAINS, WHITELIST_DOMAINS)
__loadList(FILE_BLACKLIST_STRINGS, BLACKLIST_STRINGS)
__loadList(FILE_DOMAINS_TLDS,      DOMAINS_TLDS)

##########################################################################################

# VIRUSTOTAL VARS AND CONST

URL_VIRUSTOTAL               = 'https://www.virustotal.com/vtapi/v2/file/report'
virustotalEnabled            = False # Set to True if you want to perform a scan
virustotalApiKey             =  ""
virustotalResource           =  ""
virustotalUnlimitedNames     = False

##########################################################################################

# TEST FUNCTIONS 

def __test_MSO_macros(path):
	o = __execute([FILE_PYTHON, FILE_DEPENDENCIES_OLEDUMP, path])
	__debug(o)
	if not re.search("no OLE file was found", o):
		if re.search(" M | O | E | \! ", o): # 'm' omitted to prevent false positives
			__alert("Macro detected")
		else:
			__warning("Possible active content found")

def __test_PDF_objects(path):
	o = __execute([FILE_PYTHON, FILE_DEPENDENCIES_PDF_PARSER, "--stats", path])
	__debug(o)
	if re.search("/JS|/JavaScript|/AA|/OpenAction|/Launch", o):
		__alert("Active content detected")
	if re.search("/JBIG2Decode|/RichMedia|/XFA", o):
		__warning("Interesting content detected")

def __test_ALL_patterns(path):
	__test_ALL_pattern(path, REGEX_IPV4, WHITELIST_IPV4, "IPv4")
	__test_ALL_pattern(path, REGEX_URLS, WHITELIST_URLS, "URL")
	__test_ALL_domains(path, REGEX_DOMAINS, DOMAINS_TLDS, WHITELIST_DOMAINS)
def __test_ALL_pattern(path, pattern, whitelist, label):
	fileContent = __getFileContent(path)
	matches  = re.findall(pattern, fileContent)
	matches  = list(dict.fromkeys(matches)) # Remove duplicates

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

def __test_ALL_domains(path, pattern, tlds, whitelist):
	# If domains Detection is not enabled by the user exit the function immediately
	if not domainsDetection:
		return

	fileContent = __getFileContent(path)
	matches  = re.findall(pattern, fileContent)
	matches  = list(dict.fromkeys(matches)) # Remove duplicates

	foundElements = []
	if matches:
		for match in matches:
			for tld in tlds:
				if match.endswith(tld):
					for exclusion in whitelist:
						if exclusion in match:
							break
					else:
						foundElements.append(match)

	foundElements = list(dict.fromkeys(foundElements)) # Remove duplicates
	if foundElements:
		if verbose == False:
			__info("Domain scheme detected in " + str(path))
		else:
			for foundElement in foundElements:
				__verbose("Pattern Domain found (" + foundElement + ") in " + str(path))

def __test_ALL_strings(path):
	fileContent = __getFileContent(path)
	for badstring in BLACKLIST_STRINGS:
		if re.search(badstring, fileContent, re.IGNORECASE):
			__warning("Bad string '" + badstring + "' found in " + str(path))

def __test_ARCHIVE(path):
	# Extract the archive in /$tmp/first-contact/$archive-name
	extractionDirectory = os.path.join(FOLDER_TEMP, Path(path).stem)
	if Path(extractionDirectory).is_dir():
		__error("A previous file extraction was found: " + str(extractionDirectory) + ". Analysis stopped: please consider deleting the old folder first")
		exit()

	__verbose("Extracting as archive into " + str(extractionDirectory))
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
			__test_ALL_patterns(filePath)
			__test_ALL_strings(filePath)

	# Remove extracted files
	if keepAfterExtraction == False:
		shutil.rmtree(extractionDirectory)

##########################################################################################

# VIRUSTOTAL REPORT

def __getVirustotalReport(hash):
	httpPostData = {
    'apikey': virustotalApiKey,
    'resource': hash,
    'allinfo' : 'true'
    }
 
	httpResponse = requests.post(URL_VIRUSTOTAL, data = httpPostData)

	print("\nVirusTotal report\n")
	__debug(httpResponse.text)
	if httpResponse.status_code == 200:
		try:
			j = json.loads(httpResponse.text)
			fileStatus = int(j["response_code"])
			if fileStatus == 1:
				print("Name        : " + str(j["submission_names"][0]) + "\n")
				print("Detections  : " + str(j["positives"]) + "/" + str(j["total"]))
				print("Reputation  : " + str(j["community_reputation"]) + " (-100 is fully malicious, 100 is fully harmless)\n")
				print("Last  scan  : " + str(j["scan_date"]))
				print("First seen  : " + str(j["first_seen"]) + "\n")
				print("Other names : \n")
				if virustotalUnlimitedNames == True:
					for name in j["submission_names"]:
						print("             " + name)
				else:
					for name in j["submission_names"][:10]:
						print("             " + name)
			elif fileStatus == 0:
					print("The item you searched for was not present in VirusTotal's dataset")
			elif fileStatus == -2:
					print("The requested item is still queued for analysis")
			else:
					print("Unknow file status " + fileStatus + ".")
		except Exception as e:
			__debug(e)
			__error("error parsing JSON data")

	elif httpResponse.status_code == 204:
		print("Request rate limit exceeded. You are making more requests than allowed. You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.")
	elif httpResponse.status_code == 400:
		print("Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.")
	elif httpResponse.status_code == 403:
		print("Forbidden. You don't have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges.")
	else:
		print("Unknow error " +  httpResponse.status_code + ".")

	print("")

##########################################################################################

# CALCULATE FILE HASH

def __getHash(path):
	if not os.path.exists(path):
		__error("Invalid file given")
		exit()

	with open(path, 'rb') as f:
		sha1   = hashlib.sha1()
		sha256 = hashlib.sha256()
		md5    = hashlib.md5()

		while True:
			chunk = f.read(16 * 1024)
			if not chunk:
				break
			sha1.update(chunk)
			sha256.update(chunk)
			md5.update(chunk)

		return str(md5.hexdigest()), str(sha1.hexdigest()), str(sha256.hexdigest());

##########################################################################################

# START 

def __main():
	# Check if at least one argument is passed
	if len(sys.argv) == 1:
		__error("No arguments given")
		__help()
	
	# Parse arguments by shift
	args = sys.argv[1:]
	while len(args):
		if args[0]   == "-h" or args[0] == "--help":
			__help()
		elif args[0] == "-v" or args[0] == "--verbose":
			global verbose 
			verbose = True
			__verbose("verbose output enabled")
		elif args[0] == "-d" or args[0] == "--debug":
			global debug 
			debug = True
			__debug("debug output enabled")
		elif args[0] == "-D" or args[0] == "--domains":
			global domainsDetection 
			domainsDetection = True
		elif args[0] == "-f" or args[0] == "--force-mime":
			if not args[1] is None:
				global forceMime
				global forcedMime 
				forceMime = True
				forcedMime = args[1]
				args = args[1:] # additional shift
			else:
				__error("No MIME given.")
		elif args[0] == "-k" or args[0] == "--keep-after-extraction":
			global keepAfterExtraction
			keepAfterExtraction = True
		elif args[0] == "-c" or args[0] == "--checksum":
			global printChecksum
			printChecksum = True
		elif args[0] == "-V" or args[0] == "--virustotal":
			if not args[1] is None:
				global virustotalApiKey
				virustotalApiKey = args[1]
				global virustotalEnabled
				virustotalEnabled = True
				args = args[1:] # additional shift
			else:
				__error("VirustTotal API Key not given.")
		elif args[0] == "-Vun" or args[0] == "--virustotal-unlimited-names":
			global virustotalUnlimitedNames
			virustotalUnlimitedNames = True
		else:
			file = args[0]
		args = args[1:] # shift

	# Check if file parameter is populated
	try:
		file = Path(file)
	except:
		__error("Invalid file given")
		__help()

	# Check if file exists
	if not Path(file).is_file():
		__error("Invalid file given")
		__help()

	print("")

	if printChecksum:
		md5, sha1, sha256 = __getHash(file)
		print("NAME        : " + os.path.basename(file))
		print("MD5         : " + md5)
		print("SHA1        : " + sha1)
		print("SHA256      : " + sha256)
		print("")

	if virustotalEnabled:
		md5, sha1, sha256 = __getHash(file)
		__getVirustotalReport(md5)

	# Get file MIME
	mime = __getMime(file)
	__debug("MIME found " + mime)

	# If forced MIME is enabled, overwrite detected MIME
	if forceMime:
		mime = forcedMime
		__verbose("forcing MIME " + mime)

	# Run a test based on the MIME detected
	if re.search("Word|Excel|openxmlformats", mime, re.IGNORECASE):
		__info("MS Office file detected")
		__test_MSO_macros(file)
		__test_ALL_patterns(file)
		__test_ALL_strings(file)
		__test_ARCHIVE(file)
	elif re.search("PDF", mime, re.IGNORECASE):
		__info("Portable Document Format file detected")
		__test_PDF_objects(file)
		__test_ALL_patterns(file)
		__test_ALL_strings(file)
	else:
		__info("Unsupported file type: Performing generic tests")
		__test_ALL_patterns(file)
		__test_ALL_strings(file)
		__test_ARCHIVE(file)

	__info("Analysis complete.\n")
if __name__ == "__main__":
	__main()