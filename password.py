import tkinter as tk
import re
import math

#Password Checking Logic

def calculate_entropy(password):
    pool = 0

    if re.search(r'[a-z]', password):
        pool += 26
    if re.search(r'[A-Z]', password):
        pool += 26
    if re.search(r'[0-9]', password):
        pool += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        pool += 32

    if pool == 0:
        return 0

    entropy = len(password) * math.log2(pool)
    return round(entropy, 2)


def check_strength(password):
    score = 0

    # Length check
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1

    # Regex checks
    if re.search(r'[a-z]', password):
        score += 1
    if re.search(r'[A-Z]', password):
        score += 1
    if re.search(r'[0-9]', password):
        score += 1
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 1

    # Strength decision
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Medium"
    else:
        return "Strong"


# -------- GUI -------- #

def evaluate_password():
    pwd = entry.get()

    if pwd == "":
        result_label.config(text="Enter a password", fg="red")
        entropy_label.config(text="")
        return

    strength = check_strength(pwd)
    entropy = calculate_entropy(pwd)

    result_label.config(text=f"Strength: {strength}", fg="blue")
    entropy_label.config(text=f"Entropy: {entropy} bits")


# -------- Tkinter Window -------- #

root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x250")

# Title
title = tk.Label(root, text="Password Strength Checker", font=("Arial", 14))
title.pack(pady=10)

# Input
entry = tk.Entry(root, width=30, show="*")
entry.pack(pady=10)

# Button
check_btn = tk.Button(root, text="Check Strength", command=evaluate_password)
check_btn.pack(pady=5)

# Result Labels
result_label = tk.Label(root, text="", font=("Arial", 12))
result_label.pack(pady=5)

entropy_label = tk.Label(root, text="", font=("Arial", 10))
entropy_label.pack(pady=5)

# Run App
root.mainloop()