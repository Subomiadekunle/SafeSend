# gui_receiver.py
import threading
import tkinter as tk
from tkinter import scrolledtext

# Import both run_server and set_logger so we can route logs to the GUI
from safesend.receiver import run_server, set_logger


class ReceiverGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SafeSend Receiver")

        # Scrolling log window
        self.log = scrolledtext.ScrolledText(root, width=80, height=20, state="normal")
        self.log.pack(padx=10, pady=10)

        # Start button
        self.btn = tk.Button(root, text="Start Receiver", command=self.start_server)
        self.btn.pack(pady=10)

        self.running = False

    def append_log(self, msg: str):
        """
        Thread-safe: schedule UI updates on the Tkinter main thread.
        """
        def _do_insert():
            self.log.insert(tk.END, msg + "\n")
            self.log.see(tk.END)

        self.root.after(0, _do_insert)

    def start_server(self):
        if self.running:
            return

        self.running = True
        self.append_log("[GUI] Starting SafeSend receiver on port 9000...")

        # Route receiver logs into this GUI before starting the server thread
        set_logger(self.append_log)

        thread = threading.Thread(target=self.wrapper, daemon=True)
        thread.start()

    def wrapper(self):
        try:
            # Pass logger to run_server as well (extra safety)
            run_server(9000, logger=self.append_log)
        except Exception as e:
            self.append_log(f"[ERROR] {e}")


if __name__ == "__main__":
    root = tk.Tk()
    ReceiverGUI(root)
    root.mainloop()
