#!/usr/bin/env python3
import sys
import os

BaseDir = os.path.dirname(os.path.abspath(__file__))

for folder in ['modules']:
    path = os.path.join(BaseDir, folder)
    if path not in sys.path:
        sys.path.insert(0, path)

from purplest import main
main.run(baseDir=BaseDir)
