from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import webbrowser
import pygame
import hashlib
import hmac

# ===================== DES FUNCTIONS =====================

def des_encrypt(message, key):
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 8:
        raise ValueError("DES anahtarı 8 karakter olmalı")
    cipher = DES.new(key_bytes, DES.MODE_CBC)
    encrypted = cipher.encrypt(pad(message.encode("utf-8"), 8))
    return base64.b64encode(cipher.iv + encrypted).decode("utf-8")

def des_decrypt(ciphertext, key):
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 8:
        raise ValueError("DES anahtarı 8 karakter olmalı")
    data = base64.b64decode(ciphertext)
    iv = data[:8]
    encrypted = data[8:]
    cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), 8)
    return decrypted.decode("utf-8")

# ===================== DES WINDOW =====================

# ====== WRAPPER WITH INTEGRITY CHECK ======
def secure_encrypt(msg, key):
    data = msg + "||" + hashlib.sha256((msg + key).encode()).hexdigest()[:8]
    return des_encrypt(data, key)

def secure_decrypt(cipher, key):
    plain = des_decrypt(cipher, key)

    if "||" not in plain:
        raise Exception("WRONG KEY OR CORRUPTED MESSAGE")

    msg, check = plain.split("||")

    valid = hashlib.sha256((msg + key).encode()).hexdigest()[:8]

    if check != valid:
        raise Exception("WRONG KEY – DECRYPTION FAILED")

    return msg

# ===================== DES WINDOW =====================
def open_des_window():
    root = tk.Tk()
    root.title("DES Cryptography Messaging")
    root.geometry("900x700")
    root.resizable(False, False)

    FONT_MAIN = ("Times New Roman", 14)
    FONT_LABEL = ("Times New Roman", 16)
    mode = None

    top_frame = tk.Frame(root)
    top_frame.pack(pady=40)

    content_frame = tk.Frame(root)

    lbl_msg = tk.Label(content_frame, text="Your Message", font=FONT_LABEL)
    lbl_msg.pack(pady=(30, 5))

    message_entry = tk.Entry(content_frame, width=50, font=FONT_MAIN, justify="center")
    message_entry.pack(ipady=8, pady=5)

    lbl_key = tk.Label(content_frame, text="Encryption Key (8 letters)", font=FONT_LABEL)
    lbl_key.pack(pady=(20, 5))

    key_entry = tk.Entry(content_frame, width=20, font=FONT_MAIN, justify="center")
    key_entry.pack(ipady=8, pady=5)

    result_text = tk.Text(content_frame, height=8, width=60, font=FONT_MAIN)
    result_text.pack(ipady=8, pady=30)
    result_text.tag_configure("center", justify="center")

    def process_message():
        try:
            result_text.delete(1.0, tk.END)

            if len(key_entry.get()) != 8:
                raise Exception("KEY MUST BE 8 CHARACTERS")

            if mode == "encrypt":
                result = secure_encrypt(message_entry.get(), key_entry.get())
            else:
                result = secure_decrypt(message_entry.get(), key_entry.get())

            result_text.insert("1.0", result, "center")

        except Exception as e:
            messagebox.showerror("ERROR", str(e))

    action_btn = tk.Button(content_frame, text="PROCESS", font=FONT_MAIN, command=process_message)
    action_btn.pack(pady=20)

    btn_encrypt = tk.Button(top_frame, text="ENCRYPT", font=FONT_MAIN)
    btn_encrypt.pack(side="left", padx=40)

    btn_decrypt = tk.Button(top_frame, text="DECRYPT", font=FONT_MAIN)
    btn_decrypt.pack(side="left", padx=40)

    widgets = [lbl_msg, lbl_key, message_entry, key_entry, result_text, action_btn, btn_encrypt, btn_decrypt]

    def apply_theme(bg, fg, entry_bg, entry_fg):
        root.configure(bg=bg)
        top_frame.configure(bg=bg)
        content_frame.configure(bg=bg)

        for w in widgets:
            if isinstance(w, tk.Label):
                w.configure(bg=bg, fg=fg)
            elif isinstance(w, tk.Button):
                w.configure(bg=bg, fg=fg, activebackground=bg,
                            activeforeground=fg, relief="flat", bd=0)
            elif isinstance(w, (tk.Entry, tk.Text)):
                w.configure(bg=entry_bg, fg=entry_fg,
                            insertbackground=entry_fg, relief="flat", bd=0)

    def show_content():
        if not content_frame.winfo_ismapped():
            content_frame.pack()

    def set_encrypt_mode():
        nonlocal mode
        mode = "encrypt"
        show_content()
        apply_theme("#ebdbdb", "#3d0208", "#3d0208", "#ebdbdb")

    def set_decrypt_mode():
        nonlocal mode
        mode = "decrypt"
        show_content()
        apply_theme("#3d0208", "#ebdbdb", "#ebdbdb", "#3d0208")

    btn_encrypt.configure(command=set_encrypt_mode)
    btn_decrypt.configure(command=set_decrypt_mode)

    root.mainloop()

    # ---------- MODE BUTTONS ----------
    btn_encrypt = tk.Button(top_frame, text="ENCRYPT", font=FONT_MAIN)
    btn_encrypt.pack(side="left", padx=40)

    btn_decrypt = tk.Button(top_frame, text="DECRYPT", font=FONT_MAIN)
    btn_decrypt.pack(side="left", padx=40)

    widgets = [lbl_msg, lbl_key, message_entry, key_entry, result_text, action_btn, btn_encrypt, btn_decrypt]

    # ---------- THEME ----------
    def apply_theme(bg, fg, entry_bg, entry_fg):
        root.configure(bg=bg)
        top_frame.configure(bg=bg)
        content_frame.configure(bg=bg)
        for w in widgets:
            if isinstance(w, tk.Label):
                w.configure(bg=bg, fg=fg)
            elif isinstance(w, tk.Button):
                w.configure(bg=bg, fg=fg, activebackground=bg, activeforeground=fg, relief="flat", bd=0)
            elif isinstance(w, (tk.Entry, tk.Text)):
                w.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg, relief="flat", bd=0)

    # ---------- CONTENT SHOW ----------
    def show_content():
        if not content_frame.winfo_ismapped():
            content_frame.pack()

    # ---------- MODES ----------
    def set_encrypt_mode():
        nonlocal mode
        mode = "encrypt"
        show_content()
        apply_theme("#ebdbdb", "#3d0208", "#3d0208", "#ebdbdb")

    def set_decrypt_mode():
        nonlocal mode
        mode = "decrypt"
        show_content()
        apply_theme("#3d0208", "#ebdbdb", "#ebdbdb", "#3d0208")

    btn_encrypt.configure(command=set_encrypt_mode)
    btn_decrypt.configure(command=set_decrypt_mode)

    root.mainloop()

# ===================== AES FUNCTIONS =====================

from Crypto.Cipher import AES
import os

def aes_encrypt(message, key):
    key_bytes = key.encode("utf-8")

    if len(key_bytes) != 16:
        raise ValueError("AES anahtarı 16 karakter olmalı")

    iv = os.urandom(16)

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(message.encode("utf-8"), 16))

    # integrity tag
    tag = hmac.new(key_bytes, iv + encrypted, hashlib.sha256).digest()[:8]

    return base64.b64encode(iv + encrypted + tag).decode("utf-8")


def aes_decrypt(ciphertext, key):
    key_bytes = key.encode("utf-8")

    if len(key_bytes) != 16:
        raise ValueError("AES anahtarı 16 karakter olmalı")

    data = base64.b64decode(ciphertext)

    iv = data[:16]
    tag = data[-8:]
    encrypted = data[16:-8]

    # verify integrity FIRST
    valid_tag = hmac.new(key_bytes, iv + encrypted, hashlib.sha256).digest()[:8]

    if tag != valid_tag:
        raise Exception("WRONG KEY OR CORRUPTED MESSAGE")

    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), 16)

    return decrypted.decode("utf-8")

# ===================== AES WINDOW =====================

def open_aes_window():
    root = tk.Tk()
    root.title("AES Cryptography Messaging")
    root.geometry("900x700")
    root.resizable(False, False)

    FONT_MAIN = ("Times New Roman", 14)
    FONT_LABEL = ("Times New Roman", 16)
    mode = None

    top_frame = tk.Frame(root)
    top_frame.pack(pady=40)

    content_frame = tk.Frame(root)

    lbl_msg = tk.Label(content_frame, text="Your Message", font=FONT_LABEL)
    lbl_msg.pack(pady=(30, 5))

    message_entry = tk.Entry(content_frame, width=50, font=FONT_MAIN, justify="center")
    message_entry.pack(ipady=12, pady=15, ipadx=40)

    lbl_key = tk.Label(content_frame, text="Encryption Key (16 letters)", font=FONT_LABEL)
    lbl_key.pack(pady=(20, 5))

    key_entry = tk.Entry(content_frame, width=20, font=FONT_MAIN, justify="center")
    key_entry.pack(ipady=8, pady=5, ipadx=25)

    result_text = tk.Text(content_frame, height=8, width=60, font=FONT_MAIN)
    result_text.pack(ipady=5, pady=20)
    result_text.tag_configure("center", justify="center")

    def process_message():
        try:
            result_text.delete(1.0, tk.END)
            if mode == "encrypt":
                result = aes_encrypt(message_entry.get(), key_entry.get())
            else:
                result = aes_decrypt(message_entry.get(), key_entry.get())
            result_text.insert("1.0", result, "center")
        except Exception as e:
            messagebox.showerror("ERROR", str(e))

    action_btn = tk.Button(content_frame, text="PROCESS", font=FONT_MAIN, command=process_message)
    action_btn.pack(pady=20)

    btn_encrypt = tk.Button(top_frame, text="ENCRYPT", font=FONT_MAIN)
    btn_encrypt.pack(side="left", padx=40)

    btn_decrypt = tk.Button(top_frame, text="DECRYPT", font=FONT_MAIN)
    btn_decrypt.pack(side="left", padx=40)

    widgets = [lbl_msg, lbl_key, message_entry, key_entry, result_text, action_btn, btn_encrypt, btn_decrypt]

    def apply_theme(bg, fg, entry_bg, entry_fg):
        root.configure(bg=bg)
        top_frame.configure(bg=bg)
        content_frame.configure(bg=bg)
        for w in widgets:
            if isinstance(w, tk.Label):
                w.configure(bg=bg, fg=fg)
            elif isinstance(w, tk.Button):
                w.configure(bg=bg, fg=fg, activebackground=bg, activeforeground=fg, relief="flat", bd=0)
            elif isinstance(w, (tk.Entry, tk.Text)):
                w.configure(bg=entry_bg, fg=entry_fg, insertbackground=entry_fg, relief="flat", bd=0)

    def show_content():
        if not content_frame.winfo_ismapped():
            content_frame.pack()

    def set_encrypt_mode():
        nonlocal mode
        mode = "encrypt"
        show_content()
        apply_theme("#ebdbdb", "#3d0208", "#3d0208", "#ebdbdb")

    def set_decrypt_mode():
        nonlocal mode
        mode = "decrypt"
        show_content()
        apply_theme("#3d0208", "#ebdbdb", "#ebdbdb", "#3d0208")

    btn_encrypt.configure(command=set_encrypt_mode)
    btn_decrypt.configure(command=set_decrypt_mode)

    root.mainloop()

start_root = tk.Tk()
start_root.title("Welcome")
start_root.geometry("1200x600")

# ===================== ABOUT ME =====================

def open_about_me():
    about = tk.Toplevel(start_root)
    about.title("About Me")
    about.geometry("1200x700")
    about.resizable(False, False)

    canvas_about = tk.Canvas(about, width=900, height=600, highlightthickness=0)
    canvas_about.pack(fill="both", expand=True)

    bg_path = r"C:\Users\itsbe\OneDrive\Masaüstü\pyproject\boutme.png"
    bg_img = Image.open(bg_path).resize((1200, 700))
    bg_photo = ImageTk.PhotoImage(bg_img)
    canvas_about.bg_photo = bg_photo
    canvas_about.create_image(0, 0, image=bg_photo, anchor="nw")

    canvas_about.create_text(600, 140, text="Who am I?", font=("Times New Roman", 45, "bold"), fill="#CFC1C1")

    about_text = (
        "I'm Beren, a programming student born in 2005, with a deep curiosity for how technology works. "
        "Since childhood, I've been captivated by computers and games, not just as entertainment, but as puzzles waiting to be solved.\n\n"
        "As I discovered that I could turn this passion into a career, it became clear that becoming a developer was my path.\n\n"
        "I'm a quick learner with a natural drive to push my boundaries, always seeking to grow and improve. As a junior developer, I'm still building my foundation, but with hard work and persistence, I'm determined to turn my ambitions into reality."
    )

    canvas_about.create_text(600, 390, text=about_text, font=("Times New Roman", 20), fill="#ebdbdb", width=700, justify="center")

# ===================== CANVAS =====================

canvas = tk.Canvas(start_root, width=1200, height=600, highlightthickness=0)
canvas.pack(fill="both", expand=True)
start_root.resizable(False, False)

bg_path = r"C:\Users\itsbe\OneDrive\Masaüstü\pyproject\bg.png"
bg_img = Image.open(bg_path).resize((1200, 600))
bg_photo = ImageTk.PhotoImage(bg_img)
canvas.create_image(0, 0, image=bg_photo, anchor="nw")

logo_path = r"C:\Users\itsbe\OneDrive\Masaüstü\pyproject\1.PNG"
logo_img = Image.open(logo_path).resize((160, 160))
logo = ImageTk.PhotoImage(logo_img)
canvas.create_image(60, 30, image=logo)

hamburger_id = canvas.create_text(40, 80, text="≡", font=("Times New Roman", 40, "bold"), fill="#ebdbdb")
welcome_id = canvas.create_text(600, 300, text="Hey <3 Welcome", font=("Times New Roman", 45, "bold"), fill="#000000")

def cursor_heart(event=None):
    start_root.config(cursor="heart")

def cursor_default(event=None):
    start_root.config(cursor="")

MENU_W = 250
SLIDE_SPEED = 25
menu_overlay = tk.Frame(start_root, bg="#000000", width=MENU_W)
menu_overlay.place(x=-MENU_W, y=0, width=MENU_W, relheight=1)

def slide_in():
    x = menu_overlay.winfo_x()
    if x < 0:
        menu_overlay.place(x=min(x + SLIDE_SPEED, 0), y=0)
        menu_overlay.lift()
        start_root.after(10, slide_in)

def slide_out():
    x = menu_overlay.winfo_x()
    if x > -MENU_W:
        menu_overlay.place(x=max(x - SLIDE_SPEED, -MENU_W), y=0)
        start_root.after(10, slide_out)

canvas.tag_bind(hamburger_id, "<Enter>", lambda e: slide_in())
menu_overlay.bind("<Leave>", lambda e: slide_out())

def overlay_button(text, command):
    return tk.Button(menu_overlay, text=text, bg="#000000", fg="#ebdbdb", font=("Times New Roman", 14, "bold"),
                     relief="flat", cursor="heart", anchor="w", padx=20,
                     activebackground="#000000", activeforeground="#ebdbdb", command=command)

def open_contact_me():
    contact = tk.Toplevel(start_root)
    contact.title("Contact Me")
    contact.geometry("700x500")
    contact.configure(bg="#d0cccc")
    contact.resizable(False, False)

    container = tk.Frame(contact, bg="#d0cccc")
    container.pack(expand=True, fill="both")

    title = tk.Label(container, text="Contact Me", font=("Times New Roman", 30, "bold"), bg="#d0cccc", fg="#000000")
    title.pack(pady=(60, 40))

    info_frame = tk.Frame(container, bg="#d0cccc")
    info_frame.pack()

    mail_label = tk.Label(info_frame, text="Mail Address", font=("Times New Roman", 18, "bold"), bg="#d0cccc", fg="#000000")
    mail_label.pack(pady=(10, 5))

    mail_value = tk.Label(info_frame, text="berenpercinnn@gmail.com", font=("Times New Roman", 16), bg="#d0cccc", fg="#000000")
    mail_value.pack(pady=(0, 30))

    social_label = tk.Label(info_frame, text="Social Media", font=("Times New Roman", 18, "bold"), bg="#d0cccc", fg="#000000")
    social_label.pack(pady=(10, 5))

    social_link = tk.Label(info_frame, text="@ilaydapercin", font=("Times New Roman", 16, "underline"), bg="#d0cccc",
                            fg="#1a1718", cursor="hand2")
    social_link.pack()
    social_link.bind("<Button-1>", lambda e: webbrowser.open_new_tab("https://www.instagram.com/ilaydapercin/"))

pygame.mixer.init()
pygame.mixer.music.load(r"C:\Users\itsbe\OneDrive\Masaüstü\pyproject\videoplayback.mp3")
pygame.mixer.music.set_volume(0.05)
music_playing = False

def toggle_music(event=None):
    global music_playing
    if not music_playing:
        pygame.mixer.music.play(-1)
        music_playing = True
    else:
        pygame.mixer.music.stop()
        music_playing = False

canvas.tag_bind(welcome_id, "<Button-1>", toggle_music)
canvas.tag_bind(welcome_id, "<Enter>", cursor_heart)
canvas.tag_bind(welcome_id, "<Leave>", cursor_default)

import random

# ===================== CAESAR FUNCTIONS =====================

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - start + shift) % 26 + start)
        else:
            result += char
    return result

# ===================== CAESAR GAME =====================
def open_caesar_game():
    game_window = tk.Toplevel()
    game_window.title("Caesar Challenge")
    game_window.geometry("1200x600")
    game_window.resizable(False, False)

    bg_path = r"C:\Users\itsbe\OneDrive\Masaüstü\pyproject\ceasar.png"
    bg_img = Image.open(bg_path).resize((1200, 600))
    bg_photo = ImageTk.PhotoImage(bg_img)

    canvas = tk.Canvas(game_window, width=1200, height=600, highlightthickness=0)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=bg_photo, anchor="nw")
    canvas.bg_photo = bg_photo

    FONT_MAIN = ("Times New Roman", 20, "bold")
    FONT_RESULT = ("Times New Roman", 25, "bold")
    FONT_RESULT_DISPLAY = ("Times New Roman", 25, "bold")
    FONT_BTN = ("Times New Roman", 14, "bold")

    sentences = [
        "The moon hides truths the sun fears to reveal.",
        "Ancient whispers crawl along the walls when no one is watching.",
        "The forest remembers the footsteps of those who never left",
        "A single candle can ignite a hundred forgotten memories.",
        "Stars are eyes of gods, watching the world’s unspoken sins.",
    ]

    original_sentence = random.choice(sentences)
    shift = random.randint(1, 10)
    encrypted_sentence = caesar_encrypt(original_sentence, shift)

    tries_left = [5]

    def show_custom_window(title, content, width=800, height=250, wraplength=750):
        window = tk.Toplevel(game_window)
        window.title(title)
        window.geometry(f"{width}x{height}")
        window.resizable(False, False)
        tk.Label(
            window,
            text=content,
            font=FONT_RESULT_DISPLAY,
            fg="black",
            bg="white",
            wraplength=wraplength,
            justify="center"
        ).pack(expand=True, fill="both")

    def reveal_shift():
        show_custom_window("Shift Number", f"The shift number used is: {shift}")

    def show_tips():
        tips_text = (
            "💡 Caesar Cipher Tips:\n"
            "1. Each letter is shifted by the same number (shift).\n"
            "2. Example: If D → A, shift = 3.\n"
            "3. Apply the same shift to all letters.\n"
            "4. Only letters are shifted; punctuation and spaces stay the same.\n\n"
            "Alphabet:\nABCDEFGHIJKLMNOPQRSTUVWXYZ"
        )
        show_custom_window("Tips", tips_text, width=900, height=400, wraplength=850)

    def show_result():
        show_custom_window("Decrypted Sentence", original_sentence)

    def check_answer():
        answer = entry_var.get().strip()
        if answer.lower() == original_sentence.lower():
            canvas.delete("all")
            canvas.configure(bg="black")
            canvas.create_text(600, 250, text="YOU WON!", font=FONT_RESULT, fill="white")
            play_again_btn = tk.Button(
                game_window, text="Go Again", font=FONT_BTN,
                bg="black", fg="white", bd=0, highlightthickness=0,
                command=lambda: [game_window.destroy(), open_caesar_game()]
            )
            canvas.create_window(600, 350, window=play_again_btn)
        else:
            tries_left[0] -= 1
            if tries_left[0] > 0:
                show_custom_window("Wrong", f"Incorrect! You have {tries_left[0]} tries left.")
            else:
                canvas.delete("all")
                canvas.configure(bg="black")
                canvas.create_text(600, 250, text="YOU LOST!", font=FONT_RESULT, fill="white")
                play_again_btn = tk.Button(
                    game_window, text="Play Again", font=FONT_BTN,
                    bg="black", fg="white", bd=0, highlightthickness=0,
                    command=lambda: [game_window.destroy(), open_caesar_game()]
                )
                canvas.create_window(600, 350, window=play_again_btn)

    canvas.create_text(600, 150, text=encrypted_sentence, font=FONT_MAIN, fill="#959393")

    entry_var = tk.StringVar()
    user_entry = tk.Entry(
        game_window, textvariable=entry_var, font=FONT_MAIN,
        width=40, bg="#3D3D3D", fg="#959393",
        justify="center", bd=0, highlightthickness=0
    )
    canvas.create_window(600, 300, window=user_entry)
    user_entry.focus()

    # BUTONLAR
    shift_btn = tk.Button(
        game_window, text="Reveal Shift", font=FONT_BTN,
        bg="#3D3D3D", fg="#959393", bd=0, highlightthickness=0,
        command=reveal_shift
    )

    result_btn = tk.Button(
        game_window, text="Show Result", font=FONT_BTN,
        bg="#3D3D3D", fg="#959393", bd=0, highlightthickness=0,
        command=show_result
    )

    check_btn = tk.Button(
        game_window, text="Check", font=FONT_BTN,
        bg="#3D3D3D", fg="#959393", bd=0, highlightthickness=0,
        command=check_answer
    )
    canvas.create_window(375, 390, window=shift_btn)
    canvas.create_window(500, 390, window=result_btn)

    canvas.create_window(915, 300, window=check_btn)

    tips_btn = tk.Button(
        game_window, text="?", font=FONT_MAIN,
        bg="#3D3D3D", fg="#959393", bd=0, highlightthickness=0,
        command=show_tips
    )
    canvas.create_window(1150, 50, window=tips_btn)


def open_portfolio():
    webbrowser.open_new_tab("https://www.itsberen.com")

overlay_button("DES Encryption", open_des_window).pack(fill="x", pady=(30, 10))
overlay_button("AES Encryption", open_aes_window).pack(fill="x", pady=10)
overlay_button("About Me", open_about_me).pack(fill="x", pady=10)
overlay_button("My Personal Portfolio", open_portfolio).pack(fill="x", pady=10)
overlay_button("Contact Me", open_contact_me).pack(fill="x", pady=10)
overlay_button("Caesar Challenge", open_caesar_game).pack(fill="x", pady=10)

start_root.mainloop()
