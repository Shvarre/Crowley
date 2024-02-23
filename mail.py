import tkinter as tk
from tkinter import ttk
import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urljoin

def fetch_subpages():
    domain = entry.get()
    try:
        response = requests.get(domain, verify=False)
        html_content = response.text
        soup = BeautifulSoup(html_content, 'html.parser')
        subpages = []
        for link in soup.find_all('a', href=True):
            subpage_url = link['href']
            full_url = urljoin(domain, subpage_url)  # Konverterer relativ sti til absolut URL
            subpages.append(full_url)
        return subpages
    except requests.exceptions.RequestException as e:
        return []

def contains_emails(subpage_url):
    try:
        response = requests.get(subpage_url, verify=False)
        html_content = response.text
        emails = extract_emails(html_content)
        return bool(emails)
    except requests.exceptions.RequestException as e:
        return False

def extract_emails(text):
    email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_regex, text)    
    return emails

def update_subpage_list():
    subpages = fetch_subpages()
    subpage_listbox.delete(0, tk.END)
    for subpage in subpages:
        if contains_emails(subpage):
            subpage_listbox.insert(tk.END, subpage)
            subpage_listbox.itemconfig(tk.END, {'fg': 'green'})
        else:
            subpage_listbox.insert(tk.END, subpage)

def update_email_listbox(html_content):
    email_listbox.delete(0, tk.END)
    emails = extract_emails(html_content)
    for email in emails:
        email_listbox.insert(tk.END, email)

def on_email_double_click(event):
    add_email_to_list()

def on_big_list_double_click(event):
    remove_email_from_list()

def add_email_to_list():
    selected_indices = email_listbox.curselection()
    for i in selected_indices:
        email = email_listbox.get(i)
        big_listbox.insert(tk.END, email)

def remove_email_from_list():
    selected_indices = big_listbox.curselection()
    for i in selected_indices[::-1]:
        big_listbox.delete(i)

def export_emails():
    emails = big_listbox.get(0, tk.END)
    for email in emails:
        print(email)  # Skriver emails ud i terminalen

def handle_subpage_selection(event):
    selected_indices = subpage_listbox.curselection()
    if selected_indices:
        index = selected_indices[0]
        selected_subpage = subpage_listbox.get(index)
        response = requests.get(selected_subpage, verify=False)
        html_content = response.text
        output_textarea.delete(1.0, tk.END)
        output_textarea.insert(tk.END, html_content)
        update_email_listbox(html_content)

# GUI setup
root = tk.Tk()
root.title("Webcrawler")
root.geometry("1000x600")  # Juster vinduets størrelse

# Domain entry og knap i en top frame
top_frame = tk.Frame(root)
top_frame.pack(fill=tk.X)

entry = tk.Entry(top_frame)
entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

fetch_button = tk.Button(top_frame, text="Hent undersider", command=update_subpage_list)
fetch_button.pack(side=tk.RIGHT, padx=5)

# Subpages listbox
subpage_frame = tk.Frame(root)
subpage_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

subpage_listbox = tk.Listbox(subpage_frame)
subpage_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

subpage_scrollbar = tk.Scrollbar(subpage_frame, orient=tk.VERTICAL, command=subpage_listbox.yview)
subpage_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
subpage_listbox.config(yscrollcommand=subpage_scrollbar.set)

subpage_listbox.bind('<<ListboxSelect>>', handle_subpage_selection)

# Email listbox og knap
email_frame = tk.Frame(root)
email_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

email_listbox = tk.Listbox(email_frame)
email_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
email_listbox.bind('<Double-1>', on_email_double_click)

add_email_button = tk.Button(email_frame, text="Tilføj Email", command=add_email_to_list)
add_email_button.pack(pady=5)

# Scrollbar kun for email_listbox
'''
email_scrollbar = tk.Scrollbar(email_frame, orient=tk.VERTICAL, command=email_listbox.yview)
email_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
email_listbox.config(yscrollcommand=email_scrollbar.set)
'''

# Big listbox, fjern email-knap og eksport-knap
big_list_frame = tk.Frame(root)
big_list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

big_listbox = tk.Listbox(big_list_frame)
big_listbox.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
big_listbox.bind('<Double-1>', on_big_list_double_click)

remove_email_button = tk.Button(big_list_frame, text="Fjern Email", command=remove_email_from_list)
remove_email_button.pack(pady=5)

export_button = tk.Button(big_list_frame, text="Eksporter Emails", command=export_emails)
export_button.pack(pady=5)

# Output textarea
output_frame = tk.Frame(root)
output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

output_textarea = tk.Text(output_frame)
output_textarea.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

output_scrollbar = tk.Scrollbar(output_frame, orient=tk.VERTICAL, command=output_textarea.yview)
output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
output_textarea.config(yscrollcommand=output_scrollbar.set)

root.mainloop()