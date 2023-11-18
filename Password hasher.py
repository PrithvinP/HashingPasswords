import hashlib
import tkinter as tk

def generate_hash():
    password = password_entry.get()
    hash_type = hash_type_var.get()

    if hash_type == "SHA-256":
        hash_code = hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == "MD5":
        hash_code = hashlib.md5(password.encode()).hexdigest()
    else:
        hash_code = "Select a hash type"

    hashed_password_label.config(text="Hashed Password: " + hash_code)

# Create the main window
root = tk.Tk()
root.title("Password Hasher")

# Create GUI elements
password_label = tk.Label(root, text="Enter the password:")
password_label.pack()

password_entry = tk.Entry(root, show="*")
password_entry.pack()

hash_type_var = tk.StringVar()
hash_type_var.set("SHA-256")  # Default hash type

hash_type_label = tk.Label(root, text="Select the hash type:")
hash_type_label.pack()

hash_type_menu = tk.OptionMenu(root, hash_type_var, "SHA-256", "MD5")
hash_type_menu.pack()

hash_button = tk.Button(root, text="Generate Hash", command=generate_hash)
hash_button.pack()

hashed_password_label = tk.Label(root, text="")
hashed_password_label.pack()

# Start the GUI
root.mainloop()
