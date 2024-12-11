# Viktar Archive File System

## Overview
The Viktar Archive File System is a C-based program designed to manage custom archive files using UNIX file I/O system calls. It supports creating, extracting, and managing archives containing multiple files, while maintaining file metadata and ensuring data integrity with MD5 checksums.

## Features
- **Create Archive (-c)**: Combines multiple files into a single archive.
- **Extract Files (-x)**: Extracts one or more files from an archive, preserving file permissions and timestamps.
- **Short Table of Contents (-t)**: Displays a brief list of the files in the archive.
- **Long Table of Contents (-T)**: Provides detailed information about each file in the archive.
- **Validate Files (-V)**: Verifies the integrity of archived files using MD5 checksums.
- **Help (-h)**: Displays detailed usage instructions.
- **Verbose Mode (-v)**: Provides diagnostic messages during execution.

## File Structure
An archive file consists of:
1. **File Header**: Metadata for each file (name, size, permissions, timestamps, etc.).
2. **File Data**: The binary content of each archived file.
3. **File Footer**: Contains MD5 checksum values for the file header and data.

## Ensuring Data Integrity
MD5 checksums are computed for both the header and the data of each file in the archive. These checksums are stored in the footer of the archive file. During extraction, the checksums are recalculated and compared to the stored values to ensure the file content has not been altered or corrupted. If a mismatch is detected, a warning is issued, but the file is still extracted, allowing users to assess the data integrity manually.

## Build Instructions
To compile the project and create the 'viktar' executable, simply run:
```bash
make
```
This will automatically compile all necessary files and generate the viktar executable in the current directory.

## Command-Line Usage
```
viktar <options> [archive-file] [member [...]]
```

### Options
- `-c`: Create an archive. Specify files to add as members.
- `-x`: Extract files from the archive. Extract all if no specific files are provided.
- `-t`: Display a short table of contents.
- `-T`: Display a long table of contents.
- `-f <filename>`: Specify the archive file name.
- `-V`: Validate MD5 checksums of the archive.
- `-h`: Show help text.
- `-v`: Enable verbose diagnostic messages.

### Examples
- Create an archive:
  ```
  ./viktar -c -f myarchive.viktar file1.txt file2.txt
  ```
- Extract all files from an archive:
  ```
  ./viktar -x -f myarchive.viktar
  ```
- Display a short table of contents:
  ```
  ./viktar -t -f myarchive.viktar
  ```
- Validate archive contents:
  ```
  ./viktar -V -f myarchive.viktar
  ```

## Technical Details
- Developed using low-level UNIX system calls (`open`, `read`, `write`, `lseek`, etc.).
- MD5 checksum calculations are performed for data integrity validation.
- Designed for interoperability with other Viktar archive files.
- Follows strict memory management rules (validated with `valgrind`).

## Dependencies
- **C Compiler**: `gcc` with specific flags for strict compilation.
- **MD5 Library**: Required for checksum validation. Link with `-lmd`.

