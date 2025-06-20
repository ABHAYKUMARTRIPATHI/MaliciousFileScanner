import argparse
from scanner.hash_checker import get_file_hash, check_known_hashes
from scanner.vt_checker import check_virustotal
from scanner.yara_scanner import run_yara_scan
from scanner.ml_detector import predict_file
import datetime

def log_result(file_path, verdicts):
    with open('reports/scan_log.txt', 'a') as log:
        log.write(f"{datetime.datetime.now()} - {file_path} - {verdicts}\n")

def scan_file(file_path, vt_api_key):
    file_hash = get_file_hash(file_path)
    known = check_known_hashes(file_hash)
    vt_result = check_virustotal(file_hash, vt_api_key)
    yara_result = run_yara_scan(file_path)
    ml_result = predict_file(file_path)

    print(f"\n--- Scan Report for: {file_path} ---")
    print(f"[1] Hash: {file_hash}")
    print(f"[2] Known Hash Match: {'Yes' if known else 'No'}")
    print(f"[3] VirusTotal: {vt_result}")
    print(f"[4] YARA Match: {yara_result}")
    print(f"[5] ML Prediction: {'Malicious' if ml_result else 'Benign'}")

    verdict = {
        "known_hash": known,
        "vt_result": vt_result,
        "yara": yara_result,
        "ml": "Malicious" if ml_result else "Benign"
    }

    log_result(file_path, verdict)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malicious File Scanner")
    parser.add_argument("file", help="Path to the file to scan")
    parser.add_argument("--vtkey", help="VirusTotal API Key", required=True)
    args = parser.parse_args()

    scan_file(args.file, args.vtkey)
