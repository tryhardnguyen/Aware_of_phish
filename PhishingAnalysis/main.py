import sys
import webbrowser
import requests
import os
from tabulate import tabulate
import pyfiglet


def clear_terminal():
    os.system('cls' if os.name=='nt' else 'clear')

def is_email(email):
    import re
    import os
    #Check if the file exists and that it ends with .eml
    if re.search(r"\.eml", email) and os.path.isfile(email):
        return True
    else:
        return False


def primary_menu():
    _ART = pyfiglet.figlet_format("AWARE OF PHISH", font="digital")
    _TABLE = [["1", "Email Information"], ["2", "Quick Analysis"], ["3", "Verify DKIM"]]
    _HEADERS = ["Choice", "Description"]
    print(f"{_ART}{tabulate(_TABLE, headers=_HEADERS, tablefmt='fancy_grid')}")
    

def email_information_table():
    _ART = pyfiglet.figlet_format("Email Information", font="digital")
    _TABLE = [["1", "From"], ["2", "Reply-To"], ["3","Return-Path"], ["4","Received"]]
    _HEADERS = ["Choice", "Description"]
    print(f"{_ART}{tabulate(_TABLE, headers=_HEADERS, tablefmt='grid')}")
    

def get_email_info(choice, email_path):
    import email
    from email import policy
    from email.parser import BytesParser
    
    with open(email_path, "rb") as e_file:
        data = BytesParser(policy=policy.default).parse(e_file)


def main():
    # Make sure that the email that the user provided is a valid.'
    valid_email = False
    show_menu = True
    
    while True:
        email_path = input("Please enter the path of the email (For example: /home/user/email.eml): or 'q' to quit: ")
        if is_email(email_path):
            # Process the email
            break
        elif email_path == "q":
            show_menu = False
            break
        else:
            print("The email path or email you entered is not a valid. Please try again.")
    if show_menu:
        primary_menu()
        while True:
            try:
                # This is for the primary menu
                choice = input("Please enter your choice ('q' to quit): ")
                if choice == "1":
                    clear_terminal()
                    email_information_table()
                elif choice == "2":
                    clear_terminal()
                    quick_analysis()
                elif choice == "3":
                    clear_terminal()
                    verify_dkim()
                elif choice == "q":
                    break
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Invalid choice. Please try again.")

if __name__ == '__main__':
    main()