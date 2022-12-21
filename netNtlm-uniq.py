files = input("Filename/path: ")
data = []

with open(files, 'r') as f:
        data = f.readlines()
        f.close()

uniq_data = []
uniq_data_full = []
for item in data:
        if item.split("::")[0] not in uniq_data and item.split("::")[0].find('$') == -1:
                uniq_data_full.append(item)
                uniq_data.append(item.split("::")[0])

with open("out.txt", 'w') as f:
        for thing in uniq_data_full:
                f.write(thing)
                               
