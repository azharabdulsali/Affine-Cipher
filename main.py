import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.uic import loadUi

class MainMenu(QMainWindow):
    def __init__(self):
        super().__init__()
        ui_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "views/AffineCipher.ui")
        loadUi(ui_path, self)

        self.pushButton_encrypt.clicked.connect(self.encrypt)
        self.pushButton_decrypt.clicked.connect(self.decrypt)
        self.pushButton_clear.clicked.connect(self.clear)
        self.pushButton_kunci_encrypt.clicked.connect(self.show_encryption_key)
        self.pushButton_kunci_decrypt.clicked.connect(self.show_decryption_key)

    def encrypt(self):
        plaintext = self.plainTextEdit_plain.text().upper()
        a = int(self.lineEdit_a.text())
        b = int(self.lineEdit_b.text())
        encrypted_text = self.affine_encrypt(plaintext, a, b)
        self.plainTextEdit_cipher.setText(encrypted_text)

    def decrypt(self):
        ciphertext = self.plainTextEdit_cipher.text().upper()
        a = int(self.lineEdit_a.text())
        b = int(self.lineEdit_b.text())
        decrypted_text = self.affine_decrypt(ciphertext, a, b)
        self.plainTextEdit_plain2.setText(decrypted_text)
        
    def clear(self):
        self.plainTextEdit_plain.clear()
        self.lineEdit_a.clear()
        self.lineEdit_b.clear()
        self.plainTextEdit_cipher.clear()
        self.plainTextEdit_plain2.clear()

    def show_encryption_key(self):
        a = int(self.lineEdit_a.text())
        b = int(self.lineEdit_b.text())
        key = f"Kunci Enkripsi: (a={a}, b={b})"
        self.show_key_dialog("Kunci Enkripsi", key)

    def show_decryption_key(self):
        a = int(self.lineEdit_a.text())
        b = int(self.lineEdit_b.text())
        a_inverse = self.mod_inverse(a, 26)
        b_inverse = (-b * a_inverse) % 26
        key = f"Kunci Dekripsi: (a={a_inverse}, b={b_inverse})"
        self.show_key_dialog("Kunci Dekripsi", key)

    def show_key_dialog(self, title, key):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle(title)
        msg.setText(key)
        msg.exec_()

    def affine_encrypt(self, plaintext, a, b):
        encrypted_text = ""
        for char in plaintext:
            if char.isalpha():
                encrypted_char = chr(((a * (ord(char) - 65) + b) % 26) + 65)
                encrypted_text += encrypted_char
            else:
                encrypted_text += char
        return encrypted_text

    def affine_decrypt(self, ciphertext, a, b):
        decrypted_text = ""
        a_inverse = self.mod_inverse(a, 26)
        for char in ciphertext:
            if char.isalpha():
                decrypted_char = chr(((a_inverse * (ord(char) - 65 - b)) % 26) + 65)
                decrypted_text += decrypted_char
            else:
                decrypted_text += char
        return decrypted_text

    def mod_inverse(self, a, m):
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainMenu = MainMenu()
    mainMenu.show()
    sys.exit(app.exec_())
