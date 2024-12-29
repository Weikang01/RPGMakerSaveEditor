import json
import base64
import lzstring
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import tkinter as tk
import itertools
from tkinter import filedialog, scrolledtext, messagebox, Menu

class BruteForceTask:
    def __init__(self, method_name, params):
        self.method_name = method_name
        self.params = params

    def execute(self, data):
        raise NotImplementedError("Subclasses must implement execute method")

class AESBruteForceTask(BruteForceTask):
    def __init__(self, key_length, iv_length):
        super().__init__("AES", {"key_length": key_length, "iv_length": iv_length})
        self.key_length = key_length
        self.iv_length = iv_length

    def execute(self, data):
        for key in itertools.product(range(256), repeat=self.key_length):
            for iv in itertools.product(range(256), repeat=self.iv_length):
                try:
                    cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))
                    decrypted = unpad(cipher.decrypt(data), AES.block_size)
                    return decrypted.decode('utf-8')
                except Exception:
                    continue
        return None

class XORBruteForceTask(BruteForceTask):
    def __init__(self, key_length):
        super().__init__("XOR", {"key_length": key_length})
        self.key_length = key_length

    def execute(self, data):
        for key in itertools.product(range(256), repeat=self.key_length):
            try:
                decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
                return decrypted.decode('utf-8')
            except Exception:
                continue
        return None

class RPGSaveProcessor:
    def __init__(self):
        self.lz = lzstring.LZString()
        self.encryption_key = None
        self.iv = None
        self.uses_aes = False
        self.uses_xor = False

    def aes_decrypt(self, decoded, encryption_key, iv):
        try:
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
            parsed = json.loads(decrypted)
            self.encryption_key = encryption_key
            self.iv = iv
            self.uses_aes = True
            return json.dumps(parsed, indent=4, sort_keys=True, ensure_ascii=False)
        except Exception as e:
            return None

    def decrypt_rpg_save(self, save: str) -> str:
        try:
            decoded = self.lz.decompressFromBase64(save)
            parsed = json.loads(decoded)
            return json.dumps(parsed, indent=4, sort_keys=True, ensure_ascii=False)
        except Exception as e:
            print(f"Default decompression failed: {e}")

        # Attempt Base64 decoding if default fails
        try:
            decoded = base64.b64decode(save)

            # Check for Zlib compression
            try:
                decompressed = zlib.decompress(decoded)
                parsed = json.loads(decompressed)
                return json.dumps(parsed, indent=4, sort_keys=True, ensure_ascii=False)
            except zlib.error:
                print("Zlib decompression failed.")
        except Exception as e:
            raise ValueError(f"Failed to decode save file: {e}")

        raise ValueError("All decryption attempts failed.")

    def encrypt_rpg_save(self, save: str) -> str:
        try:
            parsed = json.loads(save)
            minified = json.dumps(parsed, separators=(',', ':'))

            # Use AES encryption if it was detected
            if self.uses_aes:
                if not self.encryption_key or not self.iv:
                    raise ValueError("AES key and IV must be provided for encryption.")

                cipher = AES.new(self.encryption_key, AES.MODE_CBC, self.iv)
                encrypted = cipher.encrypt(pad(minified.encode('utf-8'), AES.block_size))
                return base64.b64encode(encrypted).decode('utf-8')

            return self.lz.compressToBase64(minified)
        except Exception as e:
            raise ValueError(f"Failed to encode save file: {e}")


class RPGSaveEditor:
    def __init__(self):
        self.processor = RPGSaveProcessor()
        self.title = "RPG Save Editor"
        self.content = ""
        self.window = tk.Tk()
        self.window.title(self.title)
        self.window.geometry("800x600")

        # Create menu bar
        self.menu_bar = Menu(self.window)
        self.window.config(menu=self.menu_bar)

        # File menu
        file_menu = Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Open .rpgsave", command=self.open_file)
        file_menu.add_command(label="Save", command=self.save_changes)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.window.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)

        # Text area
        self.text_area = scrolledtext.ScrolledText(self.window, wrap=tk.WORD, font=("Courier", 12))
        self.text_area.pack(expand=True, fill='both')

    def open_file(self):
        file_path = filedialog.askopenfilename(
            title="Select RPG Maker Save File",
            filetypes=[("RPG Save Files", "*.rpgsave"), ("All Files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    encrypted_data = file.read()

                decrypted_data = self.processor.decrypt_rpg_save(encrypted_data)
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, decrypted_data)
                self.content = decrypted_data
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt file: {e}")

    def save_changes(self):
        try:
            updated_content = self.text_area.get("1.0", tk.END).strip()
            re_encoded_data = self.processor.encrypt_rpg_save(updated_content)
            messagebox.showinfo("Success", "File successfully encoded!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {e}")

    def show_editor(self):
        self.window.mainloop()

# Main logic
if __name__ == '__main__':
    rpg_save_editor = RPGSaveEditor()
    rpg_save_editor.show_editor()
