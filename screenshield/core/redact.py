import threading
import tkinter as tk


def _show(boxes: list[dict], screen_w: int, screen_h: int, duration: int = 5000):
    root = tk.Tk()
    root.overrideredirect(True)
    root.attributes("-topmost", True)
    root.attributes("-alpha", 0.92)
    root.geometry(f"{screen_w}x{screen_h}+0+0")
    root.configure(bg="black")

    canvas = tk.Canvas(root, bg="black", highlightthickness=0)
    canvas.pack(fill="both", expand=True)

    if boxes:
        for b in boxes:
            x, y, w, h = b["x"], b["y"], b["w"], b["h"]
            pad = 6
            canvas.create_rectangle(
                x - pad, y - pad, x + w + pad, y + h + pad,
                fill="#ff2222", outline="#ff2222",
            )
            canvas.create_text(
                x + w // 2, y + h // 2,
                text="████",
                fill="black",
                font=("Courier", max(10, h // 2), "bold"),
            )
    else:
        # no boxes: full screen blackout
        canvas.create_rectangle(0, 0, screen_w, screen_h, fill="black", outline="")

    canvas.create_text(
        screen_w // 2, screen_h - 60,
        text="🛡  screenshield  -  secret hidden from screen share",
        fill="#ff2222",
        font=("Helvetica", 16, "bold"),
    )

    root.after(duration, root.destroy)
    root.mainloop()


def redact_on_screen(boxes: list[dict], screen_w: int, screen_h: int, duration_ms: int = 5000):
    t = threading.Thread(target=_show, args=(boxes, screen_w, screen_h, duration_ms), daemon=True)
    t.start()
    t.join(timeout=(duration_ms / 1000) + 1)
