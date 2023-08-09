# Userlist generator that uses SecLists

import argparse
import string
import sys
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description="Generates a large list of usernames for kerbrute")
    parser.add_argument('-mode', action='store', default='0', choices=['0', '1', '2', '3'], help='Select which type of username you want 0=First.Last 1==FirstletterLast 2=FirstletterMILast 3=ALL')
    parser.add_argument('-o', '--outputfile', action='store', help='File to output your usernames to. Deafult=./usernames.txt')
    parser.add_argument('-i', '--inputfile', action='store', help='Directory of SecLists/Usernames/Names EX: -i /opt/SecLists/Usernames/Names/ Default=/opt/SecLists/Usernames/Names/')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.outputfile is None:
        outfile = "./usernames.txt"
    else:
        outfile = options.outputfile

    if options.inputfile is None:
        infile = "/opt/SecLists/Usernames/Names/"
    else:
        infile = options.inputfile

    lastnames = []
    firstnames = []
    lastnames_cleand = []
    firstnames_cleaned = []
    lowercase_letters = list(string.ascii_lowercase)
    with open("{}names.txt".format(infile), 'r') as f:
        firstnames = f.readlines()
        f.close()

    with open("{}familynames-usa-top1000.txt".format(infile), 'r') as f:
        lastnames = f.readlines()
        f.close()

    for sub in firstnames:
        firstnames_cleaned.append(sub.replace('\n', '').lower())

    for sub in lastnames:
        lastnames_cleand.append(sub.replace('\n', '').lower())

    with open(outfile, 'a') as f:
        if options.mode == '0' or options.mode == '3':
            for name in firstnames_cleaned:
                for lname in lastnames_cleand:
                    f.write(name + "." + lname + "\n")

        if options.mode == '1' or options.mode == '3':
            for lname in lastnames_cleand:
                for letter in lowercase_letters:
                    f.write(letter + lname + "\n")

        if options.mode == '2' or options.mode == '3':
            for lname in lastnames_cleand:
                for char in lowercase_letters:
                    for letter in lowercase_letters:
                        f.write(letter + char + lname + "\n")

        f.close()

    if options.mode == '3':
        if sys.platform == 'linux':
            os.system('cat {} | sort -u > {}cleaned'.format(outfile, outfile))
            os.system('rm {}'.format(outfile))
            os.system('mv {}cleaned {}'.format(outfile, outfile))
        else:
            print('WARNING this file is not uniq please sort and unique it')
