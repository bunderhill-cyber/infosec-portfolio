# IP Allow List Manager

**Automated allow list updater for restricted access control**

## Project Description

This Python script was developed to maintain an allow list of IP addresses permitted to access sensitive systems. It reads an existing allow list from a file, removes any IP addresses listed in a removal list, and writes the updated allow list back to the file.

The project was created as the **capstone project** for the Google Cybersecurity Professional Certificate.

## Source & Attribution

This script is based on the final project from the following course:

> **Google Cybersecurity Professional Certificate – Course 7: Automate Cybersecurity Tasks with Python** (Coursera)

The original course material and project structure are owned by Google. This version is shared here with attribution for portfolio and learning purposes.

## Features

- Reads IP addresses from a text file (`allow_list.txt`)
- Removes specified IP addresses using a predefined removal list
- Writes the updated allow list back to the file (one IP per line)
- Includes basic documentation and clean code structure

## How It Works

1. Opens and reads the allow list file
2. Converts the file content into a list of IP addresses
3. Removes any IP addresses that appear in the `remove_list`
4. Converts the updated list back into a string
5. Overwrites the original file with the revised allow list

## Technologies Used

- Python 3
- File input/output operations
- List manipulation and string handling

## Sample Usage

```python
remove_list = [
    "192.168.97.225",
    "192.168.158.170",
    "192.168.201.40",
    "192.168.58.57"
]
