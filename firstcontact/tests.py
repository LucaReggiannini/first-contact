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
import os  # Used to join paths (cross-platform) and list files through directories
import shutil  # Used to extract archives
import socket  # Used to resolve DNS names
import tempfile  # Used to get Temp System directory (cross-platform)
from pathlib import Path  # Used to extract filenames and verify that a directory already exists

import firstcontact

FOLDER_TEMP = os.path.join(tempfile.gettempdir(), "first-contact")


#def mso_macros(file_path: str) -> None:
def mso_macros(file_path):
    try:
        print("oledump.py " + str(file_path))
        output = firstcontact.utils.execute("oledump.py \"{}\"".format(str(file_path)))
        firstcontact.out.debug(output)
    except Exception as e:
        firstcontact.out.error("Failed to execute mso_macros")
        firstcontact.out.debug(e)
        return

    if re.search("no OLE file was found", output) or re.search("is not a valid OLE file", output):
        return
    if re.search(" M | O | E | \! ", output):  # 'm' omitted to prevent false positives
        firstcontact.out.alert("Macro detected")
    else:
        firstcontact.out.warning("Possible active content found")


#def rtf_objects(file_path: str) -> None:
def rtf_objects(file_path):
    try:
        output = firstcontact.utils.execute("rtfdump.py --objects \"{}\"".format(str(file_path)))
        firstcontact.out.debug(output)
    except Exception as e:
        firstcontact.out.error("Failed to execute rtf_objects")
        firstcontact.out.debug(e)
        return

    if output and not re.search("Check if it is an RTF file", output):
        firstcontact.out.alert("Active content found")


#def pdf_objects(file_path: str, known_objects: list[str] | None) -> None:
def pdf_objects(file_path, known_objects):
    try:
        output = firstcontact.utils.execute("pdf-parser.py --stats \"{}\"".format(str(file_path)))
        firstcontact.out.debug(output)
    except Exception as e:
        firstcontact.out.error("Failed to execute pdf_objects")
        firstcontact.out.debug(e)
        return

    # Search for known objects
    if re.search("/JS|/JavaScript|/AA|/OpenAction|/Launch", output):
        firstcontact.out.alert("Active content detected")
    if re.search("/JBIG2Decode|/RichMedia|/XFA|/AcroForm", output):
        firstcontact.out.warning("Interesting content detected")
    if re.search("/Embedded", output):  # /EmbeddedFile /Embeddedfile
        firstcontact.out.alert("Embedded content detected")
    if re.search("Obj", output):  # /ObjStm /XObject
        firstcontact.out.info("Object stream detected")
    if re.search("/Encrypt", output):
        firstcontact.out.warning("The PDF document has DRM or needs a password to be read")
    if re.search("#", output):  # Detect obfuscated object in Hex form; example: /EmbeddedFile to /EmbeddedF#69le
        firstcontact.out.alert("Possible obfuscation attempt detected")

    # Search for unknown objects
    if known_objects:
        objs = re.findall(" (.*?)\s\d:\s", output)
        for obj in objs:
            for known_object in known_objects:
                if obj == known_object:
                    break
            else:
                firstcontact.out.alert("Unknown object found -> {} <-".format(obj))


#def search_pattern(
#        file_path: str,
#        pattern_name: str,
#        pattern: str,
#        whitelist: list[str] | None,
#        functions_to_run: list | None,
#        functions_to_run_args: list[list[str]] | None,
#        functions_to_run_args_pattern_index: int | None
#) -> list[str]:
def search_pattern(
        file_path,
        pattern_name,
        pattern,
        whitelist,
        functions_to_run,
        functions_to_run_args,
        functions_to_run_args_pattern_index
):
    """
    Search given Regex pattern inside a file and (optionally) call a function to perform a custom action on matched data

    Arguments:
        file_path: file to search for the pattern
        pattern_name: label used in output messages to indicate the type of pattern found
        pattern: pattern to find; must be a Regular Expression
        whitelist: list of strings to exclude from matching (can be None)
        functions_to_run: list of function to call for every element found (can be None)
        functions_to_run_args: list of (sub)lists; every (sub)list is a list of arguments to pass to the function at the same index of "functions_to_run" (can be None)
        functions_to_run_args_pattern_index: represents the index of a parameter in which to insert the matched pattern (on which to execute the function) (can be None)

    Example:
        This hypothetical script extracts the URLs from a malware
        and blocks IOCs found on the firewall via a custom function::

            # Loads actions to perform for every URL found
            numberOfDays=30
            performRetrohunt=True

            functions_to_run = [makeFirewallBlock]
            functions_to_run_args = [[foundUrl, numberOfDays, performRetrohunt]]

            # Perform test
            search_pattern(
                "/home/root/malware.bin",
                "https?://.*?/",
                ["https://google.com", "http://mysite.net"],
                "URL",
                functions_to_run,
                functions_to_run_args,
                0)

            # For every URL found (except "https://google.com" and "http://mysite.net")
            # "search_pattern" will call "makeFirewallBlock(foundUrl, 30, True)"
    """

    file_content = firstcontact.utils.get_file_content(file_path)  # Read file
    matches = re.findall(pattern, file_content)  # Perform search
    matches = list(dict.fromkeys(matches))  # Remove duplicates entries

    found_elements = []
    if whitelist is None:
        whitelist = []
    if matches:
        for match in matches:
            # For every matched result, check if is whitelisted
            for exclusion in whitelist:
                if exclusion in match:
                    break
            else:
                # If matched result is not whitelisted, add to found elements
                found_elements.append(match)

    found_elements = list(dict.fromkeys(found_elements))  # Remove duplicates entries

    # Print found elements
    if found_elements:
        firstcontact.out.warning("{} scheme detected in {}".format(pattern_name, file_path))
        for found_element in found_elements:
            firstcontact.out.verbose("Pattern {} found ({}) in {}".format(pattern_name, found_element, file_path))

        # Call custom functions for every element found
        for found_element in found_elements:
            if functions_to_run and functions_to_run_args and functions_to_run_args_pattern_index is not None:
                index = 0
                for function in functions_to_run:
                    args = functions_to_run_args[index]
                    args[functions_to_run_args_pattern_index] = found_element
                    function(*args)
                    index += 1

    return found_elements

#def search_domains(
#        file_path: str,
#        pattern: str,
#        tlds: list[str],
#        whitelist: list[str] | None,
#        functions_to_run: list | None,
#        functions_to_run_args: list[list[str]] | None,
#        functions_to_run_args_domain_index: int | None
#) -> list:
def search_domains(
        file_path,
        pattern,
        tlds,
        whitelist,
        functions_to_run,
        functions_to_run_args,
        functions_to_run_args_domain_index
):
    """
    Search domain using given Regex pattern inside a file and (optionally) call a function to perform a custom action on
    matched data.

    Arguments:
        file_path: file to search for the pattern
        pattern: pattern to find; must be a Regular Expression
        tlds: list of valid TLDs with which the pattern must end (this mechanism is used to exclude false positives given by filenames with a structure similar to that of domains)
        whitelist: list of strings to exclude from matching (can be None)
        functions_to_run: list of function to call for every element found (can be None)
        functions_to_run_args: list of (sub)lists; every (sub)list is a list of arguments to pass to the function at the same index of "functions_to_run" (can be None)
        functions_to_run_args_domain_index: represents the index of a parameter in which to insert the matched pattern (on which to execute the function) (can be None)

    Example:
        This hypothetical script extracts the URLs from a malware and blocks IOCs found on the firewall via a custom function::

            # Loads actions to perform for every URL found
            numberOfDays=30
            performRetrohunt=True

            functions_to_run = [makeFirewallBlock]
            functions_to_run_args = [[foundDomain, numberOfDays, performRetrohunt]]

            # Perform test
            search_domains(
                "/home/root/malware.bin",
                "((?:(?<!\w)[a-zA-Z0-9\-]{1,63}\.)*(?:(?<!\w)[a-zA-Z0-9\-]{1,63})(?:\.(?:[a-zA-Z0-9\-]{1,63})(?!\w)))",
                [".com", ".net"],
                ["adobe.com", "google.com"],
                functions_to_run,
                functions_to_run_args,
                0)

            # For every ".com" and ".net" Domain found (except "adobe.com" and "google.net")
            # "search_domains" will call "makeFirewallBlock(foundDomain, 30, True)"
    """

    file_content = firstcontact.utils.get_file_content(file_path)  # Read file
    matches = re.findall(pattern, file_content)  # Perform search
    matches = list(dict.fromkeys(matches))  # Remove duplicates entries

    found_elements = []
    if whitelist is None:
        whitelist = []
    if matches:
        for match in matches:
            for tld in tlds:
                if match.endswith(tld):
                    # For every matched result, check if is whitelisted
                    for exclusion in whitelist:
                        if exclusion in match:
                            break
                    else:
                        # If matched result is not whitelisted, add to found elements
                        found_elements.append(match)

    found_elements = list(dict.fromkeys(found_elements))  # Remove duplicates entries
    # Print found elements
    if found_elements:
        firstcontact.out.info("Domain scheme detected in {}".format(file_path))
        for found_element in found_elements:
            # Check if name is resolvable by DNS
            try:
                socket.gethostbyname(found_element)
                firstcontact.out.warning("Valid Domain found ({}) in {}".format(found_element, file_path))
            except socket.error:
                firstcontact.out.verbose("Pattern Domain found ({}) in {}".format(found_element, file_path))

        for found_element in found_elements:
            # Call custom functions for every element found
            if functions_to_run and functions_to_run_args and functions_to_run_args_domain_index is not None:
                index = 0
                for function in functions_to_run:
                    args = functions_to_run_args[index]
                    args[functions_to_run_args_domain_index] = found_element
                    function(*args)
                    index += 1

    return found_elements


#def search_strings(file_path: str, blacklist: list[str]) -> None:
def search_strings(file_path, blacklist):
    """
    Search blacklisted strings in file (case-insensitive)

    Arguments:
        file_path: file to search for strings
        blacklist: list of strings to search

    Example:
        ::

            search_strings("/home/root/sus.doc", ["cmd.exe", "powershell"])
    """
    file_content = firstcontact.utils.get_file_content(file_path)
    for bad_string in blacklist:
        if re.search(bad_string, file_content, re.IGNORECASE):
            firstcontact.out.warning("Bad string {} found in {}".format(bad_string, file_path))


#def test_archive(
#        file_path: str,
#        recursion: bool,
#        recursion_parent_archive_name: str | None,
#        keep_after_extraction: bool,
#        functions_to_run: list | None,
#        functions_to_run_args: list[list[str]] | None,
#        functions_to_run_args_pattern_index: int | None
#) -> None:
def test_archive(
        file_path,
        recursion,
        recursion_parent_archive_name,
        keep_after_extraction,
        functions_to_run,
        functions_to_run_args,
        functions_to_run_args_pattern_index
):
    """
    Extract files from archive and (optionally) call a function to perform a custom action on matched data.

    Arguments:
        file_path: file to search for the pattern
        recursion: set to True if the function was called recursively (extraction of an archive that was previously in another archive)
        recursion_parent_archive_name: name of the archive from where this file was originally extracted (can be set to None if the file was not in any archive)
        keep_after_extraction: if True, do not delete the extracted files after the custom functions have been called
        functions_to_run: list of function to call for every element found (can be None)
        functions_to_run_args: list of (sub)lists; every (sub)list is a list of arguments to pass to the function at the same index of "functions_to_run" (can be None)
        functions_to_run_args_pattern_index: represents the index of a parameter in which to insert the matched pattern (on which to execute the function) (can be None)

    Example:
        ::

            # This hypothetical script extracts files from
            # an archive and searches it on Virustotal
            #

            def uploadToVirustotal(apiKey, resource):
                # Some code...

            def uploadToVirustotal_wrapper(extracted_file_path):
                apiKey="rkg41tb9jkr361dmf3eokpbh5cxv0zzlvafvwlkz3rnvdbl5ampcvt5y9vsbfh5"
                fileHash=getHash(extracted_file_path)
                uploadToVirustotal(apiKey, fileHash)

            functions_to_run = [uploadToVirustotal_wrapper]
            functions_to_run_args = [[extracted_file]]

            # Perform test
            test_archive(
                "/home/root/malware.zip",
                False,
                None,
                functions_to_run,
                functions_to_run_args,
                0)

            # For every extracted file it will calculate the hash and search it on Virustotal
    """

    filename_without_extension = Path(file_path).stem
    # Extract the archive into System Temp Folder -> "first-contact" -> archive name (without extension)

    # Check if the archive was inside another archive (recursive extraction)
    if recursion:
        if not recursion_parent_archive_name:
            recursion_parent_archive_name = "archive"  # if empty set a default value
        # If the archive was inside another archive add the parent archive name
        # in front of the extraction directory name (parentArchive_archiveName)
        extraction_directory = os.path.join(
            FOLDER_TEMP,
            recursion_parent_archive_name + "_" + filename_without_extension)
    else:
        extraction_directory = os.path.join(
            FOLDER_TEMP,
            Path(file_path).stem)

    # If the extraction folder already exists, exit the program
    if Path(extraction_directory).is_dir():
        firstcontact.out.error(
            "analysis stopped because a previous file extraction was found"
            "({}); please consider deleting the old folder first".format(extraction_directory))
        exit()

    firstcontact.out.debug("Extracting (as) archive into {}".format(extraction_directory))
    try:
        # Archive extraction
        shutil.unpack_archive(file_path, extraction_directory)
    except:
        try:
            # If Shutil fails to recognize the archive
            # format, attempts to extract as ZIP format
            shutil.unpack_archive(
                file_path,
                extraction_directory,
                "zip")
        except:
            firstcontact.out.error("Can not extract as archive.")
            return

    # Get file list from directory recursively
    for root, dirs, files in os.walk(extraction_directory):
        for file in files:
            extracted_file_path = os.path.join(root, file)
            # Perform a custom functions for every file
            if functions_to_run and functions_to_run_args and functions_to_run_args_pattern_index is not None:
                index = 0
                for function in functions_to_run:
                    args = functions_to_run_args[index]
                    args[functions_to_run_args_pattern_index] = extracted_file_path
                    function(*args)
                    index += 1

            # Launch recursive extraction
            test_archive(
                extracted_file_path,
                True,  # Set to True because this is a recursive extraction
                filename_without_extension,
                keep_after_extraction,
                functions_to_run,  # Functions are also performed on any files from the archive just extracted
                functions_to_run_args,
                functions_to_run_args_pattern_index)

    # Remove extracted files
    if not keep_after_extraction:
        shutil.rmtree(extraction_directory)
