file_loc = input("Enter the file you wish to replace newlines with spaces: ")
with open(file_loc, 'r') as f:
    dat = f.read()
    f.close()

dat1 = ' '.join(dat.splitlines())

with open('out.txt', 'w') as f:
    f.writelines(dat1)
    f.close()
    
