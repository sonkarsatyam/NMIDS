import tkinter as tk


def open_logs():

    window = tk.Toplevel()

    window.title("Event Logs")

    window.geometry("900x500")

    log_box = tk.Listbox(
        window,
        width=120,
        height=30,
        bg="#111111",
        fg="#00ff88"
    )

    log_box.pack(
        fill="both",
        expand=True,
        padx=10,
        pady=10
    )

    try:

        with open(
            "events.log",
            "r",
            encoding="utf-8"
        ) as file:

            lines = file.readlines()

            for line in reversed(lines):

                log_box.insert(
                    tk.END,
                    line.strip()
                )

    except FileNotFoundError:

        log_box.insert(
            tk.END,
            "No logs found."
        )