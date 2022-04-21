#!/bin/sh
mkdir "./dependencies"
mkdir "./samples"
rm -rf "./dependencies/oledump.py" "./dependencies/pdf-parser.py"
wget -c https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/oledump.py --directory-prefix ./dependencies
wget -c https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/pdf-parser.py --directory-prefix ./dependencies
pip install olefile tempfile
