with open("logs/sample.log", "r") as file:
    for line in file:
        line = line.strip()

        if line.startswith("ERROR"):
            print(line)