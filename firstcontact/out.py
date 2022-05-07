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

from termcolor import colored
import colorama

verbose_enabled = False
debug_enabled = False


def verbose(message, print_end="\n", label=None):
    colorama.init()
    if verbose_enabled:
        if label is None:
            print(colored("Verbose", "magenta") + "     : {}".format(message), end=print_end)
        else:
            print(colored("Verbose", "magenta") + "     : [{}] {}".format(label, message), end=print_end)


def debug(message, print_end="\n", label=None):
    colorama.init()
    if debug_enabled:
        if label is None:
            print(colored("Debug", "magenta") + "       : {}".format(message), end=print_end)
        else:
            print(colored("Debug", "magenta") + "       : [{}] {}".format(label, message), end=print_end)


def alert(message, print_end="\n", label=None):
    colorama.init()
    if label is None:
        print(colored("Alert", "red") + "       : {}".format(message), end=print_end)
    else:
        print(colored("Alert", "red") + "       : [{}] {}".format(label, message), end=print_end)


def warning(message, print_end="\n", label=None):
    colorama.init()
    if label is None:
        print(colored("Warning", "yellow") + "     : {}".format(message), end=print_end)
    else:
        print(colored("Warning", "yellow") + "     : [{}] {}".format(label, message), end=print_end)


def info(message, print_end="\n", label=None):
    colorama.init()
    if label is None:
        print("Info        : {}".format(message), end=print_end)
    else:
        print("Info        : [{}] {}".format(label, message), end=print_end)


def error(message, print_end="\n", label=None):
    colorama.init()
    if label is None:
        print("Error       : {}".format(message), end=print_end)
    else:
        print("Error       : [{}] {}".format(label, message), end=print_end)
