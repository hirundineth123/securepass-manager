import sys
import json
import base64
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton,
    QLineEdit, QLabel, QListWidget, QMessageBox
)
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

DATA_FILE = "vault.dat"
SALT = b"static_salt_123" 

# Key from password
def derive_key(password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encryption happens here
def encrypt_data(key, data):
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

# Decryption happens here 
def decrypt_data(key, token):
    f = Fernet(key)
    return json.loads(f.decrypt(token).decode())

class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 400, 400)

        self.layout = QVBoxLayout()

        self.label = QLabel("Enter Master Password")
        self.layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)

        self.login_btn = QPushButton("Unlock")
        self.login_btn.clicked.connect(self.unlock)
        self.layout.addWidget(self.login_btn)

        self.setLayout(self.layout)

    def unlock(self):
        password = self.password_input.text()
        self.key = derive_key(password)

        try:
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, "rb") as f:
                    encrypted = f.read()
                    self.data = decrypt_data(self.key, encrypted)
            else:
                self.data = []

            self.show_dashboard()

        except:
            QMessageBox.critical(self, "Error", "Wrong password!")

    def show_dashboard(self):
        # Clear old layout
        for i in reversed(range(self.layout.count())):
            self.layout.itemAt(i).widget().setParent(None)

        self.list_widget = QListWidget()
        self.layout.addWidget(self.list_widget)

        self.load_data()

        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("Website")
        self.layout.addWidget(self.site_input)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        self.layout.addWidget(self.user_input)

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.layout.addWidget(self.pass_input)

        self.add_btn = QPushButton("Add")
        self.add_btn.clicked.connect(self.add_entry)
        self.layout.addWidget(self.add_btn)

    def load_data(self):
        self.list_widget.clear()
        for entry in self.data:
            self.list_widget.addItem(f"{entry['site']} | {entry['username']}")

    def add_entry(self):
        entry = {
            "site": self.site_input.text(),
            "username": self.user_input.text(),
            "password": self.pass_input.text()
        }

        self.data.append(entry)

        encrypted = encrypt_data(self.key, self.data)
        with open(DATA_FILE, "wb") as f:
            f.write(encrypted)

        self.load_data()

        self.site_input.clear()
        self.user_input.clear()
        self.pass_input.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())
