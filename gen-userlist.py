# Userlist generator that uses SecLists

import argparse
import sys

letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help = True, description = "Generates a large list of usernames for kerbrute")
    parser.add_argument('-mode', action='store', default='0', choices=['0', '1', '2', '3'], help='Select which type of username you want 0=First.Last 1==FirstletterLast 2=FirstletterMILast 3=ALL')
    parser.add_argument('-o', '--outputfile', action='store', help='File to output your usernames to')
    parser.add_argument('-i', '--inputfile', action='store', help='Directory of SecLists/Usernames/Names EX: -if /opt/SecLists/Usernames/Names/')
    
    if len(sys.argv)==1:
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
    with open("{}names.txt".format(infile), 'r') as f:
        firstnames = f.readlines()
        f.close()

    with open("{}familynames-usa-top1000.txt".format(infile), 'r') as f:
        lastnames = f.readlines()
        f.close()

    for sub in firstnames:
        firstnames_cleaned.append(sub.replace('\n', ''))

    for sub in lastnames:
        lastnames_cleand.append(sub.replace('\n', ''))

    with open(outfile, 'a') as f:
        if options.mode == '0' or options.mode == '3':
            for name in firstnames_cleaned:
                for lname in lastnames_cleand:
                    f.write(name + "." + lname + "\n")
        
        if options.mode == '1' or options.mode == '3':        
            for name in firstnames_cleaned:
                for lname in lastnames_cleand:
                    f.write(name[:1] + lname + "\n")    
                
        if options.mode == '2' or options.mode == '3':        
            for name in firstnames_cleaned:
                for char in letters:
                    for lname in lastnames_cleand:
                        f.write(name[:1] + char + lname + "\n")         
               
