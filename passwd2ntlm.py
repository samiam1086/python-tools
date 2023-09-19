import sys
try:
    from passlib.hash import ntlm
except BaseException:
    print('Missing passlib imstall with pip3 install passlib')
    sys.exit(1)


if __name__ == '__main__':
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv or '-help' in sys.argv:
        print('Usage: python3 passwd2ntlm.py \'password\'')
        sys.exit(0)
    print(nthash.hash(sys.argv[1]))
