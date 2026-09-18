import json


def save_json_report(report_data, output_file):
    try:
        with open(output_file, "w") as file:
            json.dump(
                report_data,
                file,
                indent=4
            )

        print("\nJSON report saved to", output_file)

    except OSError:
        print(
            "ERROR: Could not write JSON report to",
            output_file
        )