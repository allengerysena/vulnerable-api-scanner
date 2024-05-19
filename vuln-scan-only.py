import subprocess
import argparse

def run_script(script_name, file_name):
    command = f"python3 {script_name} -f {file_name}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    
    if process.returncode == 0:
        print(f"{stdout.decode()}")
    else:
        print(f"Error in {script_name}:\n{stderr.decode()}")

def main(file_name):
    scripts = [
        "tools/detect_hhi.py",
        "tools/detect_lfi.py",
        "tools/detect_rfi.py",
        "tools/detect_sqli.py",
        "tools/detect_ssti.py",
        "tools/detect_xss.py"
    ]

    for script in scripts:
        run_script(script, file_name)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run multiple detection scripts with a specified file.")
    parser.add_argument("-f", "--file", required=True, help="The name of the file to be used by the scripts.")
    args = parser.parse_args()

    main(args.file)
