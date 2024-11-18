import tkinter as tk
from tkinter import messagebox, ttk
import string
import secrets
import math
import requests
import os
import threading
import time

# Constants
COMMON_PASSWORDS_URL = "https://raw.githubusercontent.com/dwyl/english-words/master/words.txt"
PASSWORD_HISTORY_FILE = "password_history.txt"

# Fetch common passwords from an online source
def fetch_common_passwords():
    """Fetch a list of common passwords from an online source or use a fallback."""
    try:
        response = requests.get(COMMON_PASSWORDS_URL)
        if response.status_code == 200:
            return set(response.text.splitlines())
        else:
            messagebox.showerror("Error", "Failed to fetch common passwords. Using local list.")
            return set()
    except requests.RequestException:
        messagebox.showerror("Error", "Failed to fetch common passwords. Using local list.")
        return set()

# Fetch the list of common passwords
COMMON_PASSWORDS = fetch_common_passwords()

# Password generation logic
def generate_password(length, include_upper, include_digits, include_special):
    """Generates a password based on selected criteria, ensuring it's cryptographically secure."""
    char_pool = string.ascii_lowercase
    
    if include_upper:
        char_pool += string.ascii_uppercase
    if include_digits:
        char_pool += string.digits
    if include_special:
        char_pool += string.punctuation

    if len(char_pool) == 0:
        raise ValueError("At least one character type must be selected.")
    
    # Generate password using cryptographically secure random choices
    password = ''.join(secrets.choice(char_pool) for _ in range(length))

    # Regenerate if the password is too common
    while password in COMMON_PASSWORDS:
        password = ''.join(secrets.choice(char_pool) for _ in range(length))
    
    return password

# Calculate password entropy
def calculate_entropy(password):
    """Calculates the entropy of a given password based on character set size."""
    char_set_size = len(set(password))
    entropy = math.log2(char_set_size ** len(password))
    return entropy

# Provide feedback based on entropy
def get_strength_feedback(entropy):
    """Generates feedback about password strength based on entropy value."""
    if entropy < 40:
        return "Weak", "red"
    elif entropy < 60:
        return "Moderate", "yellow"
    else:
        return "Strong", "green"

# Handle password generation on button click
def on_generate():
    """Generate a secure password based on user input and display results."""
    try:
        length = int(length_entry.get())
        if length < 8:
            messagebox.showerror("Error", "Password length must be at least 8 characters.")
            return
        
        # Get options from checkboxes
        include_upper = upper_case_var.get()
        include_digits = digits_var.get()
        include_special = special_var.get()

        # Generate password in a separate thread to avoid blocking the GUI
        threading.Thread(target=generate_password_thread, args=(length, include_upper, include_digits, include_special)).start()

    except ValueError:
        messagebox.showerror("Error", "Please enter a valid length.")

def generate_password_thread(length, include_upper, include_digits, include_special):
    """Threaded function to handle password generation to avoid UI freeze."""
    try:
        password = generate_password(length, include_upper, include_digits, include_special)
        entropy = calculate_entropy(password)
        strength, color = get_strength_feedback(entropy)

        # Update GUI elements on the main thread
        root.after(0, update_password_display, password, strength, color, entropy)
        
    except Exception as e:
        root.after(0, messagebox.showerror, "Error", str(e))

# Update password display after generation
def update_password_display(password, strength, color, entropy):
    """Update the password field and strength label with new results."""
    password_var.set(password)
    strength_label.config(text=f"Strength: {strength} (Entropy: {entropy:.2f} bits)", fg=color)
    update_progress_bar(entropy)

# Update progress bar based on entropy
def update_progress_bar(entropy):
    """Update progress bar based on calculated password entropy."""
    progress = min(entropy / 100, 1)  # Normalize entropy to a range [0, 1]
    progress_bar["value"] = progress * 100

# Copy password to clipboard
def on_copy():
    """Copy the generated password to clipboard."""
    root.clipboard_clear()
    root.clipboard_append(password_var.get())
    messagebox.showinfo("Success", "Password copied to clipboard!")

# Save the generated password to a file
def save_password_history(password):
    """Save the generated password to a local file for future reference."""
    try:
        with open(PASSWORD_HISTORY_FILE, "a") as file:
            file.write(password + "\n")
    except IOError:
        messagebox.showerror("Error", "Failed to save password history.")

# Show password history
def on_show_history():
    """Display the history of previously generated passwords."""
    if os.path.exists(PASSWORD_HISTORY_FILE):
        try:
            with open(PASSWORD_HISTORY_FILE, "r") as file:
                history = file.readlines()
                history_text = "".join(history)
        except IOError:
            history_text = "Error reading history file."
    else:
        history_text = "No password history available."
    messagebox.showinfo("Password History", history_text)

# Clear password history
def on_clear_history():
    """Clear the saved password history."""
    if os.path.exists(PASSWORD_HISTORY_FILE):
        try:
            os.remove(PASSWORD_HISTORY_FILE)
            messagebox.showinfo("Success", "Password history cleared.")
        except IOError:
            messagebox.showerror("Error", "Failed to clear password history.")
    else:
        messagebox.showinfo("No History", "No history file found.")

# Clear generated password
def on_clear_password():
    """Clear the current generated password."""
    password_var.set("")
    strength_label.config(text="Strength: Not generated", fg="black")
    progress_bar["value"] = 0

# Main GUI setup using Tkinter
root = tk.Tk()
root.title("Futuristic Secure Password Generator")
root.geometry("500x650")
root.config(bg="#2C3E50")

# Set up the frame for the main window
frame = tk.Frame(root, padx=20, pady=20, bg="#2C3E50")
frame.pack(padx=20, pady=20, fill="both", expand=True)

# Configure fonts
heading_font = ("Helvetica", 16, "bold")
label_font = ("Helvetica", 12)
entry_font = ("Helvetica", 12)
button_font = ("Helvetica", 10, "bold")

# Set up UI components
heading_label = tk.Label(frame, text="Futuristic Secure Password Generator", font=("Helvetica", 20, "bold"), fg="#ECF0F1", bg="#2C3E50")
heading_label.grid(row=0, column=0, columnspan=2, pady=10)

# Password length input
length_label = tk.Label(frame, text="Password Length:", font=label_font, fg="#ECF0F1", bg="#2C3E50")
length_label.grid(row=1, column=0, sticky="w", pady=5)
length_entry = tk.Entry(frame, width=15, font=entry_font)
length_entry.grid(row=1, column=1, pady=5)

# Password customization checkboxes
upper_case_var = tk.BooleanVar()
digits_var = tk.BooleanVar()
special_var = tk.BooleanVar()

upper_case_check = tk.Checkbutton(frame, text="Include Uppercase Letters", variable=upper_case_var, font=label_font, fg="#ECF0F1", bg="#2C3E50", selectcolor="#2980B9")
upper_case_check.grid(row=2, columnspan=2, sticky="w", pady=5)

digits_check = tk.Checkbutton(frame, text="Include Digits", variable=digits_var, font=label_font, fg="#ECF0F1", bg="#2C3E50", selectcolor="#2980B9")
digits_check.grid(row=3, columnspan=2, sticky="w", pady=5)

special_check = tk.Checkbutton(frame, text="Include Special Characters", variable=special_var, font=label_font, fg="#ECF0F1", bg="#2C3E50", selectcolor="#2980B9")
special_check.grid(row=4, columnspan=2, sticky="w", pady=5)

# Password output display
password_label = tk.Label(frame, text="Generated Password:", font=label_font, fg="#ECF0F1", bg="#2C3E50")
password_label.grid(row=5, column=0, sticky="w", pady=5)
password_var = tk.StringVar()
password_entry = tk.Entry(frame, textvariable=password_var, width=30, font=entry_font, state="readonly")
password_entry.grid(row=5, column=1, pady=5)

# Password strength feedback
strength_label = tk.Label(frame, text="Strength: Not generated", font=label_font, fg="black", bg="#2C3E50")
strength_label.grid(row=6, columnspan=2, pady=5)

# Progress bar for strength feedback
progress_bar = ttk.Progressbar(frame, orient="horizontal", length=200, mode="determinate")
progress_bar.grid(row=7, columnspan=2, pady=10)

# Action buttons
generate_button = tk.Button(frame, text="Generate Password", font=button_font, bg="#4CAF50", fg="white", command=on_generate)
generate_button.grid(row=8, column=0, pady=10)

copy_button = tk.Button(frame, text="Copy to Clipboard", font=button_font, bg="#2196F3", fg="white", command=on_copy)
copy_button.grid(row=8, column=1, pady=10)

show_history_button = tk.Button(frame, text="Show Password History", font=button_font, bg="#FFC107", fg="white", command=on_show_history)
show_history_button.grid(row=9, column=0, pady=10)

clear_history_button = tk.Button(frame, text="Clear History", font=button_font, bg="#F44336", fg="white", command=on_clear_history)
clear_history_button.grid(row=9, column=1, pady=10)

clear_password_button = tk.Button(frame, text="Clear Password", font=button_font, bg="#9E9E9E", fg="white", command=on_clear_password)
clear_password_button.grid(row=10, columnspan=2, pady=10)

# Start the Tkinter event loop
root.mainloop()
