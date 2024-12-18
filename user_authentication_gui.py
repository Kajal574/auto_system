import tkinter as tk
from tkinter import messagebox
import sqlite3
import bcrypt

# Database setup
DB_NAME = "auth_system.db"

def initialize_db():
    # Create the database and table if they don't exist
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Authentication System
class AuthSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("User Authentication System")
        self.root.geometry("400x300")
        self.root.configure(bg="#F0F8FF")  # Light blue background

        # Current User Session
        self.current_user = None

        # Main Frame
        self.main_frame = tk.Frame(self.root, bg="#F0F8FF", padx=10, pady=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(self.main_frame, text="Welcome to the Authentication System", font=("Arial", 14, "bold"), bg="#F0F8FF", fg="#00008B").pack(pady=10)
        tk.Button(self.main_frame, text="Login", command=self.login_window, bg="#4682B4", fg="white", font=("Arial", 12)).pack(fill=tk.X, pady=5)
        tk.Button(self.main_frame, text="Register", command=self.register_window, bg="#4682B4", fg="white", font=("Arial", 12)).pack(fill=tk.X, pady=5)

    def login_window(self):
        login_win = tk.Toplevel(self.root)
        login_win.title("Login")
        login_win.geometry("300x200")
        login_win.configure(bg="#E6E6FA")

        tk.Label(login_win, text="Username:", bg="#E6E6FA", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
        tk.Label(login_win, text="Password:", bg="#E6E6FA", font=("Arial", 12)).grid(row=1, column=0, padx=5, pady=5)

        username = tk.Entry(login_win)
        password = tk.Entry(login_win, show="*")

        username.grid(row=0, column=1, padx=5, pady=5)
        password.grid(row=1, column=1, padx=5, pady=5)

        def login():
            uname = username.get().strip()
            pwd = password.get().strip()

            if not uname or not pwd:
                messagebox.showerror("Error", "Both fields are required!")
                return

            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("SELECT password, role FROM users WHERE username = ?", (uname,))
            user = cursor.fetchone()
            conn.close()

            if user and bcrypt.checkpw(pwd.encode(), user[0].encode()):
                self.current_user = {'username': uname, 'role': user[1]}
                messagebox.showinfo("Success", f"Welcome, {uname}!")
                login_win.destroy()
                self.dashboard_window()
            else:
                messagebox.showerror("Error", "Invalid credentials!")

        tk.Button(login_win, text="Login", command=login, bg="#4682B4", fg="white", font=("Arial", 12)).grid(row=2, columnspan=2, pady=10)

    def register_window(self):
        register_win = tk.Toplevel(self.root)
        register_win.title("Register")
        register_win.geometry("300x250")
        register_win.configure(bg="#E6E6FA")

        tk.Label(register_win, text="Username:", bg="#E6E6FA", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5)
        tk.Label(register_win, text="Password:", bg="#E6E6FA", font=("Arial", 12)).grid(row=1, column=0, padx=5, pady=5)
        tk.Label(register_win, text="Role (admin/user):", bg="#E6E6FA", font=("Arial", 12)).grid(row=2, column=0, padx=5, pady=5)

        username = tk.Entry(register_win)
        password = tk.Entry(register_win, show="*")
        role = tk.Entry(register_win)

        username.grid(row=0, column=1, padx=5, pady=5)
        password.grid(row=1, column=1, padx=5, pady=5)
        role.grid(row=2, column=1, padx=5, pady=5)

        def register():
            uname = username.get().strip()
            pwd = password.get().strip()
            user_role = role.get().strip()

            if not uname or not pwd or not user_role:
                messagebox.showerror("Error", "All fields are required!")
                return

            if user_role not in ['admin', 'user']:
                messagebox.showerror("Error", "Role must be 'admin' or 'user'")
                return

            hashed_pwd = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()

            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()

            try:
                print(f"Inserting user {uname} with role {user_role}")  # Debug print to see the inserted data
                cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (uname, hashed_pwd, user_role))
                conn.commit()
                messagebox.showinfo("Success", "User registered successfully!")
                register_win.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists!")
            except sqlite3.DatabaseError as e:
                messagebox.showerror("Database Error", f"An error occurred: {e}")
            finally:
                conn.close()

        tk.Button(register_win, text="Register", command=register, bg="#4682B4", fg="white", font=("Arial", 12)).grid(row=3, columnspan=2, pady=10)

    def dashboard_window(self):
        if not self.current_user:
            messagebox.showerror("Error", "Unauthorized access!")
            return

        dashboard_win = tk.Toplevel(self.root)
        dashboard_win.title(f"Dashboard - {self.current_user['username']}")
        dashboard_win.geometry("300x200")
        dashboard_win.configure(bg="#F5F5DC")

        tk.Label(dashboard_win, text=f"Welcome, {self.current_user['username']}!", font=("Arial", 14, "bold"), bg="#F5F5DC", fg="#00008B").pack(pady=10)
        tk.Label(dashboard_win, text=f"Role: {self.current_user['role']}", font=("Arial", 12), bg="#F5F5DC").pack(pady=5)

        if self.current_user['role'] == 'admin':
            tk.Label(dashboard_win, text="Admin Panel", font=("Arial", 12, "italic"), bg="#F5F5DC", fg="#8B0000").pack(pady=5)
        else:
            tk.Label(dashboard_win, text="User Panel", font=("Arial", 12, "italic"), bg="#F5F5DC", fg="#006400").pack(pady=5)

        tk.Button(dashboard_win, text="Logout", command=lambda: self.logout(dashboard_win), bg="#4682B4", fg="white", font=("Arial", 12)).pack(pady=10)

    def logout(self, win):
        self.current_user = None
        win.destroy()
        messagebox.showinfo("Info", "Logged out successfully!")

if __name__ == "__main__":
    initialize_db()  # Ensure the database is set up
    root = tk.Tk()
    app = AuthSystem(root)
    root.mainloop()
