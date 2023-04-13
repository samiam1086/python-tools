import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('file', action='store', type=str, help='The file to compare to')
	parser.add_argument('file1', action='store', type=str, help='The file to compare to')
	parser.add_argument('-of', action='store', type=str, default='out.txt', help='File to output to')
	parser.add_argument('-s', action='store_true', default=False, help='Silence the console output')
	options = parser.parse_args()


with open(options.file, 'r') as f:
    dat = f.readlines()
    f.close()


with open(options.file1, 'r') as f:
    dat1 = f.readlines()
    f.close()
   
dat1_cleaned = []
dat_cleaned = []
end_dat = []

for item in dat1:
    item = item.replace("\r", "")
    dat1_cleaned.append(item.replace("\n", ""))

for item in dat:
    item = item.replace("\r", "")
    dat_cleaned.append(item.replace("\n", ""))

for item in dat1_cleaned:
    if item in dat_cleaned:
        end_dat.append(item)

if options.s == False:
    for item in end_dat:
        print(item)

if options.of is not None:
    with open(options.of, 'w') as f:
        for item in end_dat:
            f.write(item + '\n')
