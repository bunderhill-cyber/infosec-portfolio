"""
IP Allow List Manager
A Python script used to maintain an allow list of IP addresses for restricted
patient record access in a healthcare environment.
"""

import_file = "allow_list.txt"

# List of IP addresses to be removed
remove_list = [
    "192.168.97.225",
    "192.168.158.170",
    "192.168.201.40",
    "192.168.58.57"
]

def update_allow_list():
    """Update the allow_list.txt by removing IPs from remove_list."""
    
    # Read the file
    with open(import_file, "r") as file:
        ip_addresses = file.read()
    
    # Convert string to list
    ip_addresses = ip_addresses.split()
    
    # Remove IPs that are in the remove_list
    for element in ip_addresses[:]:          # Use copy to avoid modification issues
        if element in remove_list:
            ip_addresses.remove(element)
    
    # Convert back to string with newlines
    ip_addresses = "\n".join(ip_addresses)
    
    # Write updated list back to file
    with open(import_file, "w") as file:
        file.write(ip_addresses)
    
    print("[+] Allow list has been successfully updated.")

if __name__ == "__main__":
    update_allow_list()