
first-contact Copyright 2017, 2022 Luca Reggiannini

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

```
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
	-h, --help show this manual
```
