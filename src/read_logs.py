file = open("logs/sample.log", "r")

for line in file:
    print(line)

file.close()