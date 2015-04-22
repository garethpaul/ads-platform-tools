#!/usr/bin/env python
"""
 Copyright (C) 2015 Twitter Inc and other contributors.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 """

import argparse
import csv
import re
import hashlib
import sys


def setup(args, flags):
    """Sets up arguments and flags for processing hashes.

    Args:
        args: named to setup type, infile and outfile

    Returns:
        boolean: true or false

    """
    if args.type == 'MOBILEDEVICEID':
        # mobile device IDs can be a mixture of IDFA, ADID and ANDROID in a single file
        flags['regex'] = re.compile('^[a-z0-9][a-z0-9\-]+[a-z0-9]$')

    elif args.type == 'IDFA':
        # flags['uppercase'] = True
        flags['regex'] = re.compile('^[a-z0-9][a-z0-9\-]+[a-z0-9]$')

    elif args.type == 'ADID':
        flags['regex'] = re.compile('^[a-z0-9][a-z0-9\-]+[a-z0-9]$')

    elif args.type == 'ANDROID':
        flags['regex'] = re.compile('^[a-z0-9]+$')

    elif args.type == 'EMAIL':
        flags['regex'] = re.compile('^[a-z0-9][a-z0-9_\-\.\+]+\@[a-z0-9][a-z0-9\.]+[a-z]$')

    elif args.type == 'PHONE' or args.type == 'TWITTERID':
        flags['dropleadingzeros'] = True
        flags['regex'] = re.compile('^\d+$')

    elif args.type == 'TWITTERSCREENNAME':
        flags['dropleadingat'] = True
        flags['regex'] = re.compile('^[a-z0-9_]+$')

    else:
        # There is an invalid type.
        print ("ERROR: invalid type")
        return False


    # Flags should be correctly set if so return a true value
    return True

def hashFile(args, flags):
    """Hashes the file based on the params setup in args.

    Args:
        args: named to setup type, infile and outfile

    Returns:
        dict: {"written": N, "skipped": N}

    """
    skipped = 0
    written = 0

    if args.infile.name.endswith(".csv"):
        csv_file = True
        reader = csv.reader(args.infile, dialect='excel')

    else:
        csv_file = False
        reader = args.infile

    for text in reader:
        if not csv_file:
            text = [text]

        for line in text:

            if not line: break

            line = line.rstrip()

            # Remove whitespace
            line = ''.join(line.split())

            # Set case
            if flags['uppercase']:
                line = line.upper()
            else:
                line = line.lower()

            # Drop leading '@'
            if flags['dropleadingat']:
                line = line.lstrip('@')

            # Drop leading zeros
            if flags['dropleadingzeros']:
                line = line.lstrip('0')

            if flags['regex'].match(line) is None:
                skipped += 1
                continue

            if debug:
                print ("\t" + line)

            hashed = hashlib.sha256(line).hexdigest()
            args.outfile.write(hashed + "\n")
            written += 1

    # Close --infile and --outfile
    args.infile.close()
    args.outfile.close()

    hash_info = {"written": written, "skipped": skipped}
    return hash_info

if __name__ == "__main__":
        debug = False
        parser = argparse.ArgumentParser(description='Hash the contents of a file for TA upload.')

        # Set the type.
        parser.add_argument('--type', required=True, metavar='TWITTERID', help='source data type.',
            choices=['MOBILEDEVICEID', 'IDFA', 'ADID', 'ANDROID', 'EMAIL', 'PHONE', 'TWITTERID', 'TWITTERSCREENNAME'])

        # parse --infile e.g. the in location of the file.
        parser.add_argument('--infile', required=True, type=argparse.FileType('rU'), metavar='/path/to/source.txt', help='input file to parse.')

        # parse --outfile e.g. the location of the file
        parser.add_argument('--outfile', required=True, type=argparse.FileType('w'), metavar='/path/to/output.txt', help='file to write output.')

        # Parse the arguments from the command to the variable args.
        args = parser.parse_args()

        # Setup a dictionary with Flags
        flags = {'uppercase': False, 'dropleadingzeros': False, 'dropleadingat': False }

        # If setup is correctly configured..
        if setup(args,flags) == True:
            # Run the hashFile function with the variables
            hashed_info = hashFile(args,flags)
            print ("Written:\t" + str(hashed_info['written']))
            print ("Skipped:\t" + str(hashed_info['skipped']))

        # Exit
        sys.exit()
