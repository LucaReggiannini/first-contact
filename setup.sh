#!/bin/sh
mkdir "./dependencies"
mkdir "./samples"
rm -rf "./dependencies/oledump.py" "./dependencies/pdf-parser.py" "./dependencies/rtfdump.py"
wget -c https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py --directory-prefix ./dependencies
wget -c https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py --directory-prefix ./dependencies
wget -c https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/rtfdump.py --directory-prefix ./dependencies
pip install olefile tempfile python-magic

echo "To make python-magic work please run the following commands (based on your platform):"
echo "Debian/Ubuntu : sudo apt-get install libmagic1"
echo "Windows       : pip install python-magic-bin"
echo "OSX Homebrew  : brew install libmagic"
echo "OSX macports  : port install file"