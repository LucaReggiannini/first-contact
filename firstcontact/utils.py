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

import firstcontact

import magic  # Used to detect mime types from file content
import os  # Used to join paths (cross-platform) and list files through directories
import subprocess  # Used to spawn process
import io  # Used to open files
import hashlib  # Used to calculate file hashes


# def get_hash(data: str, is_file: bool) -> tuple[str, str, str]:
def get_hash(data, is_file):
    """
    Calculates hash of a file or a array of Bytes.

    Arguments:
        data: data to be hashed
        is_file: read data as file if True, otherwise read data as Byte Array

    Returns:
        tuple: md5, sha1, sha256

    Examples:
            ::

                md5, sha1, sha256 = get_hash(file, True)
                print("MD5: {}".format(md5))
                print("SHA1: {}".format(sha1))
                print("SHA256: {}".format(sha256))
    """

    # Initialize hashlib
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    # Check if "data" is treated as a file
    if is_file:
        # Check if "data" is a valid file
        if not os.path.exists(data):
            firstcontact.out.error("Invalid file given")
            exit()

        # Read file content
        with open(data, 'rb') as f:
            while True:
                chunk = f.read(16 * 1024)
                if not chunk:
                    break

                sha1.update(chunk)
                sha256.update(chunk)
                md5.update(chunk)
    else:
        data_bytes = str.encode(data)
        md5.update(data_bytes)
        sha1.update(data_bytes)
        sha256.update(data_bytes)

    return str(md5.hexdigest()), str(sha1.hexdigest()), str(sha256.hexdigest())


#def get_mime(file_path: str) -> str:
def get_mime(file_path):
    m = magic.Magic(mime=True)
    mime = m.from_file(str(file_path))
    return mime


#def execute(program: list[str]) -> str:
def execute(program):
    """
    This function will:

    1. execute a program
    2. wait for the program to complete
    3. print output to stdout

    Arguments:
        program: list of arguments to execute

    Examples:
        output = execute(["ping", "-c", "2", "8.8.8.8"])
    """

    process = subprocess.Popen(
        program,
        stdout=subprocess.PIPE
    )
    stdout = process.communicate()[0]
    return stdout.decode('ascii', 'replace')


#def load_list(file_path: str, my_list: list) -> list:
def load_list(file_path, my_list):
    """
    Populate a list with text lines from a text file
    """
    with open(file_path) as f:
        for line in f:
            my_list.append(line.rstrip())
    return my_list


#def get_file_content(file_path: str) -> str:
def get_file_content(file_path):
    """
    Get file content in a human-readable form.

    To prevent encoding error, the error handler "surrogateescape" is used. See:
        https://peps.python.org/pep-0383/
        https://github.com/python/peps/blob/main/pep-0383.txt

    Use this function to get text from a file.
    """
    stream = io.open(
        file_path,
        mode="r",
        encoding="utf-8",
        errors="surrogateescape")

    file_content = stream.read()
    return file_content
