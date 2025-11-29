import tkinter as tk
from tkinter import filedialog, ttk
import threading
import time
from safesend.sender import send_file  # UPDATED below to support callback

class SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeSend Sender")

        # File selection button
        self.select_btn = tk.Button(root, text="Select File", command=self.select_file)
        self.select_btn.pack(pady=10)

        # Label to show selected file
        self.file_label = tk.Label(root, text="No file selected")
        self.file_label.pack()

        # Determinate progress bar
        self.progress = ttk.Progressbar(root, length=400, mode="determinate", maximum=100)
        self.progress.pack(pady=20)

        # Speed label
        self.speed_label = tk.Label(root, text="")
        self.speed_label.pack()

        # Send button
        self.send_btn = tk.Button(root, text="Send File", command=self.start_send)
        self.send_btn.pack(pady=10)

        # Status text
        self.status_label = tk.Label(root, text="")
        self.status_label.pack()

        self.filepath = None
        self.last_update_time = None
        self.last_bytes_sent = 0

    def select_file(self):
        self.filepath = filedialog.askopenfilename()
        if self.filepath:
            self.file_label.config(text=self.filepath)

    def start_send(self):
        if not self.filepath:
            self.status_label.config(text="Error: No file selected!")
            return

        self.status_label.config(text="Sending...")
        self.progress["value"] = 0
        self.speed_label.config(text="")
        self.last_update_time = time.time()

        thread = threading.Thread(target=self.send_wrapper)
        thread.daemon = True
        thread.start()

    def progress_callback(self, sent_bytes, total_bytes):
        """Called by sender.py after each chunk is successfully ACKed."""
        percent = (sent_bytes / total_bytes) * 100
        self.update_progress(percent)

        # Compute transfer speed
        now = time.time()
        elapsed = now - self.last_update_time
        if elapsed >= 0.25:
            delta = sent_bytes - self.last_bytes_sent
            speed_mb = (delta / 1024 / 1024) / elapsed
            self.speed_label.config(text=f"Speed: {speed_mb:.2f} MB/s")
            self.last_update_time = now
            self.last_bytes_sent = sent_bytes

    def update_progress(self, percent):
        self.root.after(0, lambda: self.progress.config(value=percent))

    def send_wrapper(self):
        try:
            send_file("127.0.0.1", 9000, self.filepath, progress_callback=self.progress_callback)
            self.status_label.config(text="Transfer complete!")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")
        finally:
            self.progress.stop()

root = tk.Tk()
SenderGUI(root)
root.mainloop()
