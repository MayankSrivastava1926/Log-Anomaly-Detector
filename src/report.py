def save_report(report, output_file):
    try:
        file = open(output_file, "w")

        for line in report:
            file.write(line + "\n")

        file.close()

        print("\nReport saved to", output_file)

    except OSError:
        print("ERROR: Could not write report to", output_file)