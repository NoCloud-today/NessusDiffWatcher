#!/bin/bash
SCRIPTDIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
cd $SCRIPTDIR
source venv/bin/activate
python3 NessusDiffWatcher.py 2>&1 | tee -a NessusDiffWatcher.log
#python3 NessusDiffWatcher.py --debug 2>&1 | tee -a NessusDiffWatcher.log