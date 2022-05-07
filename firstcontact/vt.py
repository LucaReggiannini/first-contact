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

import requests  # Used to make HTTP requests to VirusTotal
import json  # Used to parse JSON
import firstcontact

OUT_LABEL = "Virustotal"


def separator():
    # print("_"*100)
    pass


def get_virustotal_report(
        api_key: str,
        resource: str,
        resource_type: str,
        print_if_malicious: bool,
        files_unlimited_names: bool | None) -> bool:
    """
    Get report for given resource. If the resource is not already on Virustotal no data is uploaded.

    Args:
        api_key: your VirusTotal API KEY resource: file Hash, Domain or URL
        resource: file Hash, Domain or URL
        resource_type: possible values are "file" and "url"
        print_if_malicious: if True prints the report only if the resource is malicious
        files_unlimited_names: if True and resource is a file, prints all alternative file names for the given resource;
        (if False prints only a maximum of 10 names); if resource is not a file it can be None

    Returns:
        True if verdict is malicious, otherwise False
    """

    # Modify VirusTotal API endpoint based on the resource type
    separator()
    verdict = False

    http_payload = {
        'apikey': api_key,
        'resource': resource,
        'allinfo': 'true'
    }

    # Set HTTP request for files
    if resource_type == "file":
        http_response = requests.post("https://www.virustotal.com/vtapi/v2/file/report", data=http_payload)
    # Set HTTP request for URLs
    elif resource_type == "url":
        if not resource.startswith("http"):
            firstcontact.out.error("The URL {} does not contain the HTTP or HTTPS protocol."
                                   " Skipping...".format(resource), label=OUT_LABEL)
            return verdict
        http_response = requests.post("https://www.virustotal.com/vtapi/v2/url/report", data=http_payload)
    else:
        firstcontact.out.error("Invalid resource type given. Possible values are 'file', ""'url'",
                               label=OUT_LABEL)
        return verdict

    # Check HTTP response Code
    firstcontact.out.debug(http_response.text, label=OUT_LABEL)
    if http_response.status_code == 200:
        try:
            j = json.loads(http_response.text)
            file_status = j["response_code"]

            # Parse response JSON
            if file_status == 1:
                try:
                    name = j["submission_names"][0]
                except:
                    name = resource
                    pass

                try:
                    positives = j["positives"]
                    if int(positives) > 0:
                        verdict = True
                    total = j["total"]
                except Exception as e:
                    firstcontact.out.error("error parsing JSON data for 'positives'/'total' "
                                           "for resource {}".format(resource), label=OUT_LABEL)
                    firstcontact.out.debug(e, label=OUT_LABEL)
                    return verdict

                try:
                    community_reputation = j["community_reputation"]
                    if int(community_reputation) < 0:
                        verdict = True
                except:
                    community_reputation = "0"

                try:
                    scan_date = j["scan_date"]
                    first_seen = j["first_seen"]
                except Exception as e:
                    firstcontact.out.error("error parsing JSON data for 'scan_date' or 'first_seen' "
                                           "for resource {}".format(resource), label=OUT_LABEL)
                    firstcontact.out.debug(e, label=OUT_LABEL)
                    return verdict

                try:
                    other_names = j["submission_names"]
                except:
                    other_names = resource
                    pass

                firstcontact.out.info("VirusTotal report for {}".format(resource), label=OUT_LABEL)
                # If printIfMalicious == True and no detection is found exit the function
                if "0" in str(positives) and print_if_malicious:
                    firstcontact.out.info("No Virustotal detection", print_end="", label=OUT_LABEL)
                    try:
                        print("; community reputation is {} (-100 is fully malicious, 100 is fully harmless)".format(
                            community_reputation))
                    except:
                        pass
                    separator()
                    return verdict

                if resource_type == "file":
                    print("Name        : {}".format(name))
                # else:
                #     print("Name        : {}".format(resource))

                print("Detections  : {}/{}".format(positives, total))
                print("Reputation  : {} (-100 is fully malicious, 100 is fully harmless)".format(
                    community_reputation))
                print("Last  scan  : {}".format(scan_date))
                print("First seen  : {}".format(first_seen))

                if resource_type == "file":
                    print("Other names :")
                    if files_unlimited_names:
                        for name in other_names:
                            print("             {}".format(name))
                    else:
                        for name in other_names[:10]:
                            print("             {}".format(name))

            # Errors handling...
            elif file_status == 0:
                firstcontact.out.warning("The item you searched "
                                         "({}) for was not present in VirusTotal's dataset".format(resource),
                                         label=OUT_LABEL)
            elif file_status == -2:
                firstcontact.out.warning("The resource ({}) is still queued for analysis".format(resource),
                                         label=OUT_LABEL)
            else:
                print("Unknown file status {}.".format(file_status))
        except Exception as e:
            firstcontact.out.debug(e, label=OUT_LABEL)
            firstcontact.out.error("error parsing JSON data", label=OUT_LABEL)

    elif http_response.status_code == 204:
        firstcontact.out.error("Request rate limit exceeded. You are making more requests than allowed. You have "
                               "exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every "
                               "day at 00:00 UTC.", label=OUT_LABEL)
    elif http_response.status_code == 400:
        firstcontact.out.error("Bad request. Your request was somehow incorrect. This can be caused by missing "
                               "arguments or arguments with wrong values.", label=OUT_LABEL)
    elif http_response.status_code == 403:
        firstcontact.out.error("Forbidden. You don't have enough privileges to make the request. You may be doing a "
                               "request without providing an API key or you may be making a request to a Private API "
                               "without having the appropriate privileges.", label=OUT_LABEL)
    else:
        firstcontact.out.error("Unknown error {}.".format(http_response.status_code))

    separator()
    return verdict
