#
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
# This file is part of the "first-contact" project.
# Main repository: https://github.com/LucaReggiannini/first-contact
#

import re  # Used for Regular Expressions
import sys  # Used to parse arguments
from pathlib import Path  # Used to convert strings to paths, get filenames from paths and check if files exists
import os  # Used to join paths (cross-platform) and list files through directories
import ipaddress  # Used to check if an IP Address is public and valid
import firstcontact


def _help():
    print("""
first-contact

SYNOPSIS
    python3 -m firstcontact.firstcontact [OPTIONS...] [FILE]

DESCRIPTION
    Shows evidence of possible malware infection within some file types.
    The purpose of this program is only to automate some standard and repetitive operations that are performed during the malware analysis for certain types of documents (search for interesting strings, network IOCs, reputation checks via VirusTotal etc.)
    The analyzes on the files are performed through third-party tools: this program does not want to replace them.
    
    The following tools are used:
        pdf-parser: https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py
        oledump: https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py
        rtfdump: https://github.com/DidierStevens/DidierStevensSuite/blob/master/rtfdump.py
    
    These tools are not distributed with "first-contact" so they must be downloaded from the developer's website.
    
    For more information:
        https://github.com/DidierStevens/DidierStevensSuite
    
    Please put every third party tools on your PATH environment variable in order to use "first-contact"
    
    Tests for MS Office files:
    1. Macro detection (via oledump)
    2. URLs, IPv4 and Domains detection
    3. Blacklisted strings detection 
    4. Extraction as archive with generic tests for every files extracted

    Tests for RTF files:
    1. Objects detection (via rtfdump)
    2. URLs, IPv4 and Domains detection
    3. Blacklisted strings detection 

    Tests for PDF files:
    1. JavaScript and Action tags (via pdf-parser)
    2. JBIG2, Flash, XFA forms and Acroform (via pdf-parser)
    3. URLs, IPv4 and Domains detection
    4. Blacklisted strings detection
    5. Detect unknown or obfuscated objects (a list of known object is in <package_path>/config/knownPdfObjects.cfg)

    Generic tests (for every other file type):
    1. URLs, IPv4 and Domains detection
    2. Blacklisted strings detection 
    3. Extraction as archive with generic tests for every files extracted
    4. Virustotal report for Files and URLs 

MESSAGES TYPE:
    The program will display various types of messages:

    - Alert   : information that indicates the discovery of active code or elements recognized as malicious within the file.
                It could indicate the presence of an infection.

    - Warning : information indicating that an interesting element was found in the file. 
                A more in-depth manual analysis is required.

    - Info    : useful information to understand what the program is doing

    - Verbose : more detailed information on the data extracted from the file.
                Useful for having a precise dump of information.

    - Debug   : information that does not relate to the analysis.
                Useful for analyzing errors and solving problems within the code.
                Shows HTTP Virustotal responses and the outputs of programs used for analysis.

URLS DETECTION
    Extracts URLs from a file using a regular expression.
    
    This Regex is based on a superficial interpretation of RFC1738 so it may not work on all types of data.
    For more information: 
        https://datatracker.ietf.org/doc/html/rfc1738)

    Matches <scheme>://<scheme-specific-part> (two "slashes" have been added to the RFC definition).
    Scheme names consist of letters "a"--"z" (case insensitive), digits, and the following characters:
        "+",
        ".",
        "-".
   
    Scheme specific part can be everything until a non safe character is matched (defined in RFC):
        "<",
        ">",
        "{",
        "}",
        "|",
        "\",
        "^",
        "[",
        "]",
        "`".
        
    Omitted safe character are:
        "%",
        "#"
        "~".
    (they can be used to obfuscate malicious payloads into working URLs)

    If you want some specific results to be excluded from the match, insert them in "<package_path>/config/whitelistUrls.cfg" (one per line).
    For example, put "https://raw.githubusercontent.com" to exclude it from URL pattern match (every match that CONTAINS this string will be excluded!).

DOMAIN DETECTION
    Extract all domains from a file using a regular expression.
    
    This Regex in based on a superficial interpretation of RFC1034 so it may not work on all types of data.
    For more information:
        https://www.ietf.org/rfc/rfc1034.txt,
        http://www.tcpipguide.com/free/t_DNSLabelsNamesandSyntaxRules.htm)
    
    Matches <label-N>.<label>.<tld>.
    Labels consists of letters "a"--"z" (case insensitive), digits, and the character "-"; maximum length is 63 chars.
    Labels are separated by the character "." (you can have N label where N is an infinite number).
    The last label must be followed by the TLD.
    The TLD consists of letters "a"--"z" (case insensitive), digits, and the character "-"; maximum length is 63 chars.
    Valid TLDs must be inserted in "<package_path>/config/tlds.cfg" (current list last updated on 26-04-2022).
    If a TLD is not in this config file the domain will not match (necessary to prevent most matches with filenames whose form is similar to that of a domain name).
    For a list of valid TLDs see:
        https://www.iana.org/domains/root/db

    Since this pattern can easily match some filenames or strings contained in binary files, domain search is disabled by default to avoid false positives.
    Use option "-D" or "--domains" to enable this function.
    
    Note: potentially invalid names are also shown to highlight the presence of a match in the file.
    This could indicate the presence of parts of names within the file (which could be recomposed by the malicious code at runtime).
    For example, consider an Excel sheet with two cells containing "mal" and "ware.com/exe.exe" respectively.
    A Macro will use their contents to reassemble the complete URL "malware.com/exe.exe" which was not initially detectable.
    Domain detection will still detect "ware.com" as a possible domain: this can be a very useful wake-up call.
    Once the regular expression is used, a "Warning" is shown only for RESOLVABLE domains.
    
    If you want some specific results to be excluded from the match, insert them in the "<package_path>/config/whitelistDomains.cfg" file (one per line).
    For example, put "raw.githubusercontent.com" to exclude it from URL pattern match.

IPV4 DETECTION
    Extracts IPv4 from a file using a regular expression.
    
    This Regex matches 4 groups of numbers consisting of three digits and separated by a period.
    This will also match invalid IPv4 like 999.123.120.288 so once the regular expression is used, a "Warning" is shown only for VALID IPs that appear to belong to the public network.
    
    Note: potentially invalid or private IPs are also shown to highlight the presence of a match in the file.
    There may be hidden data in the file next to the matched data that is excluded from the regex. 
    For example in the payload "foo192.168.1.95.142.40.68bar", due to the structure of the Regex, only "192.168.1.95" is matched and not "95.142.40.68".
    This valid (potentially malicious) public IP can only be detected by examining the content of the file manually.

    If you want some specific results to be excluded from the match, insert them in the "<package_path>/config/whitelistIpv4.cfg" file (one per line).
    For example, put "127.0.0.1" to exclude it from IPv4 pattern match.

BLACKLISTED STRINGS DETECTION
    Simply searches bad strings (case insensitive) previously entered in the "<package_path>/config/blacklist.cfg" (one per line).

NOTES ON PATTERNS DETECTION
    Every detections system based on strings or Regex will NOT detect split IOC.
    For example an URL split in various Excel Sheets and "re-assembled" runtime by an Excel 4.0 Macro will NOT be detected.
    
    Remember that matches are case insensitive: if first-contact reports that it found the string "powershell", the file may also contain, for example, the string "pOwErShElL".
    Keep this in mind when doing a second manual analysis on files.

NOTES ON VIRUSTOTAL REPORTS
    Domain and IP reports are not implemented because: "Unlike file and URL reports, network location views do not record partner verdicts for the resource under consideration. Instead, these reports condense all of the recent activity that VirusTotal has seen for the resource under consideration, as well as contextual information about it."
    Source:
        https://support.virustotal.com/hc/en-us/articles/115002719069-Reports#h_c095fe17-40ce-4a5d-a561-6df598cf34d6

OPTIONS
    -h, --help 
        show this manual

    -v, --verbose 
        show more informations during execution

    -d, --debug
        show debugging informations (VirusTotal HTTP responses and complete file test results)

    -c, --checksum
        Calculate file MD5, SHA1 and SHA256

    -D, --domains
        Enable Domains detection

    -m, --mime [MIME]
        Set file MIME manually.
        Automatic MIME detection will be ignored

    -k, --keep-after-extraction
        Do not delete extracted archives content after analysis.
        Archive content is extracted in <tmp>/first-contact/<archive-name>

    -Vk, --virustotal-api-key [API_KEY]
        Required for any data from Virustotal

    -Vf, --virustotal--file-report
        Get VirusTotal report for given [FILE].
        If the file it's not already submitted no data will be uploaded

    -Vu, --virustotal--url-report
        Get VirusTotal report for every URL detected in [FILE].
        If the URL it's not already submitted no data will be uploaded
        The URL must contain HTTP/S protocol

    -Va, --virustotal-all-report
        Get VirusTotal report for given [FILE] and all URL detected inside it.
        If an element it's not already submitted no data will be uploaded.
        Equivalent to options -Vf and -Vu used together

    -Vun, --virustotal-unlimited-names
        In the VirusTotal report shows all the names with which the file has been submitted or seen in the wild.
        If this option is not activated the limit is 10 names.

    """)
    sys.exit()


# ________________________________________________________________________________________

# GENERIC VARS AND CONST

virustotal_url_report = False
virustotal_file_report = False
virustotal_unlimited_names = False
virustotal_enabled = False
virustotal_api_key = ""

domains_detection = False
keep_after_extraction = False

FILE_WHITELIST_URLS = os.path.join(os.path.dirname(sys.modules["firstcontact"].__file__), "config", "whitelistUrls.cfg")
FILE_WHITELIST_IPV4 = os.path.join(os.path.dirname(sys.modules["firstcontact"].__file__), "config", "whitelistIpv4.cfg")
FILE_WHITELIST_DOMAINS = os.path.join(os.path.dirname(sys.modules["firstcontact"].__file__), "config", "whitelistDomains.cfg")
FILE_BLACKLIST_STRINGS = os.path.join(os.path.dirname(sys.modules["firstcontact"].__file__), "config", "blacklist.cfg")
FILE_DOMAINS_TLDS = os.path.join(os.path.dirname(sys.modules["firstcontact"].__file__), "config", "tlds.cfg")
FILE_KNOWN_PDF_OBJECTS = os.path.join(os.path.dirname(sys.modules["firstcontact"].__file__), "config", "knownPdfObjects.cfg")

REGEX_URLS = "([a-zA-Z0-9\+\.\-]+:\/\/.*?)[\<|\>|\"|\{|\}|\||\\|\^|\[|\]|\`|\s|\n]"
REGEX_IPV4 = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
REGEX_DOMAINS = "((?:(?<!\w)[a-zA-Z0-9\-]{1,63}\.)*(?:(?<!\w)[a-zA-Z0-9\-]{1,63})(?:\.(?:[a-zA-Z0-9\-]{1,63})(?!\w)))"
# /http(?:s)?:\/\/(?:[\w-]+\.)*([\w-]{1,63})(?:\.(?:\w{3}|\w{2}))(?:$|\/)/i

WHITELIST_URLS = []
WHITELIST_IPV4 = []
WHITELIST_DOMAINS = []
BLACKLIST_STRINGS = []
DOMAINS_TLDS = []
KNOWN_PDF_OBJECTS = []

# Populate lists with cfg files content

firstcontact.utils.load_list(FILE_WHITELIST_URLS, WHITELIST_URLS)
firstcontact.utils.load_list(FILE_WHITELIST_IPV4, WHITELIST_IPV4)
firstcontact.utils.load_list(FILE_WHITELIST_DOMAINS, WHITELIST_DOMAINS)
firstcontact.utils.load_list(FILE_BLACKLIST_STRINGS, BLACKLIST_STRINGS)
firstcontact.utils.load_list(FILE_DOMAINS_TLDS, DOMAINS_TLDS)
firstcontact.utils.load_list(FILE_KNOWN_PDF_OBJECTS, KNOWN_PDF_OBJECTS)


# Wrapper function
def get_virustotal_file_report(resource):
    if virustotal_enabled and virustotal_file_report:
        md5, sha1, sha256 = firstcontact.utils.get_hash(resource, True)
        verdict = firstcontact.vt.get_virustotal_report(
            virustotal_api_key,
            md5,
            "file",
            True,
            virustotal_unlimited_names
        )
        if verdict:
            firstcontact.out.alert("VirusTotal reports a malicious element: {}".format(resource))


# Wrapper function
def get_virustotal_url_report(resource):
    if virustotal_enabled and virustotal_url_report:
        verdict = firstcontact.vt.get_virustotal_report(
            virustotal_api_key,
            resource,  # md5
            "url",
            True,
            None
        )
        if verdict:
            firstcontact.out.alert("VirusTotal reports a malicious element: {}".format(resource))


def check_if_valid_public_ip(ip):
    try:
        if ipaddress.ip_address(ip).is_global:
            firstcontact.out.warning("Found valid public IPv4 address: {}".format(ip))
    except:
        pass


def generic_tests(path):
    # File report
    get_virustotal_file_report(path)

    # URL detection
    # Loads actions to perform for every URL found
    url_functions_to_run = [get_virustotal_url_report]
    url_functions_to_run_args = [[""]]
    # Perform test
    firstcontact.tests.search_pattern(
        path,
        "URL",
        REGEX_URLS,
        WHITELIST_URLS,
        url_functions_to_run,
        url_functions_to_run_args,
        0)

    # IPv4 detection
    # Loads actions to perform for every URL found
    ipv4_functions_to_run = [check_if_valid_public_ip]
    ipv4_functions_to_run_args = [[""]]
    firstcontact.tests.search_pattern(
        path,
        "IPv4",
        REGEX_IPV4,
        WHITELIST_IPV4,
        ipv4_functions_to_run,
        ipv4_functions_to_run_args,
        0)

    # Load actions to perform for every domain found
    if domains_detection:
        # Perform test
        firstcontact.tests.search_domains(
            path,
            REGEX_DOMAINS,
            DOMAINS_TLDS,
            WHITELIST_DOMAINS,
            None,
            None,
            None)

    # Strings detection
    firstcontact.tests.search_strings(path, BLACKLIST_STRINGS)

    # Archive tests
    functions_to_run = [
        firstcontact.tests.search_pattern,
        firstcontact.tests.search_pattern,
        firstcontact.tests.search_domains,
        firstcontact.tests.search_strings,
    ]
    functions_to_run_args = [
        [path,
         "URL",
         REGEX_URLS,
         WHITELIST_URLS,
         url_functions_to_run,
         url_functions_to_run_args,
         0],
        [path,
         "IPv4",
         REGEX_IPV4,
         WHITELIST_IPV4,
         ipv4_functions_to_run,
         ipv4_functions_to_run_args,
         0],
        [path,
         REGEX_DOMAINS,
         DOMAINS_TLDS,
         WHITELIST_DOMAINS,
         None,
         None,
         None],
        [path, BLACKLIST_STRINGS]
    ]
    firstcontact.tests.test_archive(
        path,
        False,
        None,
        keep_after_extraction,
        functions_to_run,
        functions_to_run_args,
        0)


# ________________________________________________________________________________________

def __main():
    global virustotal_url_report
    global virustotal_file_report
    global virustotal_unlimited_names
    global virustotal_enabled
    global virustotal_api_key
    global domains_detection
    global keep_after_extraction

    print_checksum = False
    force_mime = False
    forced_mime = ""

    # Check if at least one argument is passed
    if len(sys.argv) == 1:
        firstcontact.out.error("No arguments given")
        _help()

    # Parse arguments by shift
    args = sys.argv[1:]
    while len(args):

        try:
            arg = args[0]
        except:
            pass
        try:
            val = args[1]
        except:
            pass

        if arg in ("-h", "--help"):
            _help()
        elif arg in ("-v", "--verbose"):
            firstcontact.out.verbose_enabled = True
        elif arg in ("-d", "--debug"):
            firstcontact.out.debug_enabled = True
        elif arg in ("-D", "--domains"):
            domains_detection = True
        elif arg in ("-m", "--mime"):
            if val:
                force_mime = True
                forced_mime = val
                args = args[1:]  # additional shift
            else:
                firstcontact.out.error("No MIME given.")
        elif arg in ("-k", "--keep-after-extraction"):
            keep_after_extraction = True
        elif arg in ("-c", "--checksum"):
            print_checksum = True
        elif arg in ("-Vk", "--virustotal-api-key"):
            if val:
                if re.match("[a-zA-Z0-9]{64}", val):
                    virustotal_api_key = val
                    virustotal_enabled = True
                    args = args[1:]  # additional shift
                else:
                    firstcontact.out.error("Invalid VirustTotal API Key.")
                    exit()
            else:
                firstcontact.out.error("VirustTotal API Key not given.")
                exit()
        elif arg in ("-Vun", "--virustotal-unlimited-names"):
            virustotal_unlimited_names = True
        elif arg in ("-Va", "--virustotal-all-report"):
            virustotal_url_report = True
            virustotal_file_report = True
        elif arg in ("-Vu", "--virustotal-url-report"):
            virustotal_url_report = True
        elif arg in ("-Vf", "--virustotal-file-report"):
            virustotal_file_report = True
        else:
            file = arg
        args = args[1:]  # shift

    # Check if file parameter is populated
    try:
        file = Path(file)
    except:
        firstcontact.out.error("Invalid file given")
        _help()

    # Check if file exists
    if not Path(file).is_file():
        firstcontact.out.error("Invalid file given")
        _help()

    # Check if Api Key was submitted
    if virustotal_url_report or virustotal_file_report:
        if virustotal_enabled:
            pass
        else:
            firstcontact.out.error("Virustotal options selected but no Api Key given.")
            exit()

    print("\nANALYZING   : " + os.path.basename(file))

    if print_checksum:
        md5, sha1, sha256 = firstcontact.utils.get_hash(file, True)
        print("MD5         : {}".format(md5))
        print("SHA1        : {}".format(sha1))
        print("SHA256      : {}".format(sha256))
        print("")

    # Get file MIME
    mime = firstcontact.utils.get_mime(file)
    firstcontact.out.debug("MIME found " + mime)

    # If forced MIME is enabled, overwrite detected MIME
    if force_mime:
        mime = forced_mime
        firstcontact.out.verbose("forcing MIME " + mime)

    # Run tests based on the MIME detected
    if re.search("Word|Excel|openxmlformats", mime, re.IGNORECASE):
        firstcontact.out.info("MS Office file detected")
        firstcontact.tests.mso_macros(file)
        generic_tests(file)
    elif re.search("PDF", mime, re.IGNORECASE):
        firstcontact.out.info("Portable Document Format file detected")
        firstcontact.tests.pdf_objects(file, KNOWN_PDF_OBJECTS)
        generic_tests(file)
    elif re.search("rtf", mime, re.IGNORECASE):
        firstcontact.out.info("Rich Text Format file detected")
        firstcontact.tests.rtf_objects(file)
        generic_tests(file)
    else:
        firstcontact.out.info("Unsupported file type: Performing generic tests")
        generic_tests(file)

    firstcontact.out.info("Analysis complete.\n")


if __name__ == "__main__":
    __main()
