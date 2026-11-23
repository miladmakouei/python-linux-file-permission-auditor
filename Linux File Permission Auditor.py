
import stat
from pathlib import Path


def check_permissions(path):
    try:
        file_stat = path.lstat()
        mode = file_stat.st_mode

        if stat.S_ISLNK(mode):
            return None

        is_file = stat.S_ISREG(mode)
        is_directory = stat.S_ISDIR(mode)

        if not is_file and not is_directory:
            return None

        world_writable = bool(mode & stat.S_IWOTH)

        if not world_writable:
            return None

        # Directories with the sticky bit are treated separately.
        if is_directory and mode & stat.S_ISVTX:
            return None

        return {
            "path": str(path),
            "type": "File" if is_file else "Directory",
            "permissions": stat.filemode(mode),
            "risk": "World-writable"
        }

    except OSError:
        return "ERROR"


def scan_directory(directory):
    findings = []
    scanned_files = 0
    scanned_directories = 0
    errors = 0

    paths = [directory]

    try:
        paths.extend(directory.rglob("*"))
    except OSError:
        errors += 1

    for path in paths:
        try:
            if path.is_symlink():
                continue

            if path.is_file():
                scanned_files += 1

            elif path.is_dir():
                scanned_directories += 1

            else:
                continue

            result = check_permissions(path)

            if result == "ERROR":
                errors += 1

            elif result is not None:
                findings.append(result)

        except OSError:
            errors += 1

    return {
        "findings": findings,
        "files": scanned_files,
        "directories": scanned_directories,
        "errors": errors
    }


def show_report(report):
    print("\n" + "=" * 60)
    print("             FILE PERMISSION AUDIT REPORT")
    print("=" * 60)

    print(f"\nFiles scanned:       {report['files']}")
    print(f"Directories scanned: {report['directories']}")
    print(f"Scan errors:         {report['errors']}")

    print("\nPotential Permission Issues")
    print("-" * 60)

    findings = report["findings"]

    if not findings:
        print("[+] No matching permission issues found.")

    else:
        for item in findings:
            print(f"\nType:        {item['type']}")
            print(f"Permissions: {item['permissions']}")
            print(f"Risk:        {item['risk']}")
            print(f"Path:        {item['path']}")

    print("\n" + "=" * 60)
    print(f"Total findings: {len(findings)}")
    print("Audit completed.")
    print("=" * 60)


def main():
    print("=" * 60)
    print("          LINUX FILE PERMISSION AUDITOR")
    print("=" * 60)

    user_input = input("\nEnter directory path to scan: ").strip()

    if not user_input:
        print("[-] Please enter a directory path.")
        return

    directory = Path(user_input).expanduser()

    if not directory.exists():
        print("[-] The specified path does not exist.")
        return

    if not directory.is_dir():
        print("[-] The specified path is not a directory.")
        return

    print(f"\n[*] Scanning directory: {directory}")

    report = scan_directory(directory)

    show_report(report)


if __name__ == "__main__":
    main()
