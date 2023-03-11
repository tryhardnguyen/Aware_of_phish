import sys
import os
from rich.console import Console
from rich.table import Table
from rich.style import Style

# Global variables
console = Console()

def clear_terminal():
    os.system('cls' if os.name=='nt' else 'clear')

def is_email(path_to_email):
    import binascii
    #We are going to check if the user provided an email using file signature header.
    with open(path_to_email, 'rb') as file:
        email_content = file.read()
    #Turn the email binary to hex
    hex_data = binascii.hexlify(email_content)
    # Check the file signature via email header using regex
    import re
    headers = ["52657475726e2d506174683a","44656c6976657265642d546f3a","46726f6d3a","546f","44617465"] #Return-Path:, Delivered-To:, From:, To:, Date:
    # Check for each header in hex and if one is found, then the file is a email.
    for header in headers:
        if re.search(header, str(hex_data)):
            return True
            break
        else:
            return False


def primary_menu():
    _TITLE="AWARE OF PHISH"
    _columns = ["Choice", "Description"]
    _rows = {
        "1": "Email Information",
        "2": "Verify DKIM",
        "3": "Get url",
    }
    table = Table(
        title=_TITLE, 
        title_style=Style(color="green", bold=True),
        show_lines=True, 
        row_styles=[
            Style(color="#000000", bgcolor="#709845", bold=True), 
            Style(color="#000000", bgcolor="#642d8a", bold=True), 
            Style(color="#000000", bgcolor="#f2f2c1", bold=True),
            ]
        )
    for column in _columns:
        table.add_column(column, header_style="magenta")
    for row in _rows:
        table.add_row(row, _rows[row])
    console.print(table)

def email_information_table():
    _TITLE="Email Information"
    _columns = ["Choice", "Description"]
    _rows = {
        "1": "Return-Path",
        "2": "Authentication-Results",
        "3": "Received",
        "4": "From",
        "5": "Received-SPF",
        "6": "DKIM-Signature",
    }
    # Create the Table
    table = Table(
            title=_TITLE, 
            title_style=Style(color="green", bold=True), 
            show_lines=True, 
            row_styles=[
                Style(color="#000000", bgcolor="#0080FF", bold=True),
                Style(color="#000000", bgcolor="#FFA500", bold=True), 
                Style(color="#000000", bgcolor="#008000", bold=True),
            ]
    )
    for column in _columns:
        table.add_column(column, header_style="magenta")
    for row in _rows:
        table.add_row(row, _rows[row])
    console.print(table)
    

def get_email_data(choice, email_path):
    import re
    import email
    from email import policy
    from email.parser import BytesParser
    
    menu_choice = {
        "1": "Return-Path",
        "2": "Authentication-Results",
        "3": "Received",
        "4": "From",
        "5": "Received-SPF",
        "6": "DKIM-Signature",
    }
    
    # Open the .eml file and read its contents as bytes
    with open(email_path, 'rb') as file:
        email_content = file.read()
    # Parse the email message using BytesParser
    msg = BytesParser(policy=policy.default).parsebytes(email_content)
    
    if choice == "1":
        return_path = msg["Return-Path"]
        clear_terminal()
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output", style="bold underline green")
        console.print(f"[cyan]{return_path}[/cyan]")
    elif choice == "2":
        authentication_results = msg.get_all("Authentication-Results")
        clear_terminal()
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output", style="bold underline green")
        console.print(f"[cyan]{authentication_results}[/cyan]")
    elif choice == "3": #Received
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output:", style="bold underline green")
        recieved_headers = msg.get_all("Received")
        print("The order is based on the path from the sender to the receiver.")
        print(f"Top being close to the receiver. Bottom being close to the sender.")
        for hop, header in enumerate(recieved_headers, start=1):
            from_text = re.findall(r"\(from\s[\w@]+\)|from\s[\w.]+\s\([\w.]+\s\[[\d.]+\]\)|\(from\s[\w@]+\)", header)
            by_text = re.findall(r"by\s+[\w.:]+", header)
            console.print(f"Hop: {hop}")
            if not from_text:
                console.print(f"From text: [red]not found[/red]")
                print(by_text[0])
            else:
                print(from_text[0])
                print(by_text[0])
            print()
    elif choice == "4": #From
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output:", style="bold underline green")
        from_headers = msg.get_all("From")
        print(from_headers[0])
    elif choice == "5": #Received-SPF
        console.print(f"[#FFFF00]You chose[/#FFFF00]: [red]{menu_choice[choice]}[/red]")
        console.print(f"Output:", style="bold underline green")
        received_spf = msg.get_all("Received-SPF")
        print(received_spf[0])
    elif choice == "6": #DKIM-Signature
        recieved_headers = msg.get_all("DKIM-Signature")
        if recieved_headers == None:
            print("No DKIM-Signature header found in the email")
        else:
            #Reformat the string
            for header in recieved_headers:
                v_text = re.findall(r"v=[\w]+",header)
                print(v_text[0])
                print()
                a_text = re.findall(r"a=[\w-]+;",header)
                print(a_text[0])
                print()
                c = re.findall(r"c=[\w\/]+;",header)
                print(c[0])
                print()
                d = re.findall(r"d=[\w.]+;",header)
                print(d[0])
                print()
                s = re.findall(r"s=[\w-]+;",header)
                print(s[0])
                print()
                h = re.findall(r"h=[\w:-]+;",header)
                print(h[0])
                print()
                bh = re.findall(r"bh=[\w\/=]+;",header)
                print(bh[0])
                print()
                b = re.findall(r"b=[\w+\/\s]+=",header)
                no_space = re.sub(r"\s+","",b[0])
                print(no_space)
        
def main():
    # Make sure that the email that the user provided is a valid.'
    show_menu = True
    
    while True:
        email_path = input("Please enter the path of the email (For example: /home/user/email.eml): or 'q' to quit: ")
        if email_path == "q":
            show_menu = False
            break
        try:
            if is_email(email_path):
                break
        except FileNotFoundError as e:
            console.print("File is not Found", style="red")
        else:
            console.print("Invalid File Type", style="red")
    if show_menu:
        primary_menu()
        while True:
            choice = input("Please enter your choice ('q' to quit): ")
            print()
            if choice == "q":
                break
            elif choice == "1":
                while True:
                    email_information_table()
                    sub_choice = input("Please enter your choice ('q' to quit): ")
                    print()
                    if sub_choice == "q":
                        clear_terminal()
                        break
                    elif sub_choice == "1":
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "2":
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "3":
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "4":
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "5":
                        get_email_data(sub_choice, email_path)
                        print()
                    elif sub_choice == "6":
                        get_email_data(sub_choice, email_path)
                        print()
            primary_menu()
if __name__ == '__main__':
    main()