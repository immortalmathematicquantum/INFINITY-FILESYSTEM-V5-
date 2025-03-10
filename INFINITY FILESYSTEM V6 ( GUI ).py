import os
import struct
import numpy as np
from numba import jit
import time
import tkinter as tk
from tkinter import filedialog, ttk, font

@jit(nopython=True, parallel=False)
def compute_frequencies(data):
    """Вычисляет частоты символов."""
    freqs = np.zeros(256, dtype=np.int32)
    for byte in data:
        freqs[byte] += 1
    total = np.sum(freqs)
    return freqs, total

@jit(nopython=True, parallel=False)
def build_intervals(freqs, total):
    """Создаёт интервалы для кодирования."""
    low = 0.0
    intervals = np.zeros((256, 2), dtype=np.float64)
    for byte in range(256):
        if freqs[byte] > 0:
            high = low + freqs[byte] / total
            intervals[byte, 0] = low
            intervals[byte, 1] = high
            low = high
    return intervals

@jit(nopython=True, parallel=False)
def _encode_kernel(chunk, intervals, current_low, current_high):
    """Ядро кодирования, оптимизированное Numba (без file I/O)."""
    chunk_len = len(chunk)
    for i in range(chunk_len):
        byte = chunk[i]
        range_size = current_high - current_low
        current_high = current_low + range_size * intervals[byte, 1]
        current_low = current_low + range_size * intervals[byte, 0]
    return current_low, current_high

def compress_file(input_file, output_file, chunk_size=1024*1024, progress_callback=None):
    """Сжимает файл с арифметическим кодированием, обрабатывая чанками."""
    try:
        with open(input_file, "rb") as f_in_freqs:
            data = f_in_freqs.read()
            if not data:
                return "Ошибка: входной файл пуст!"

            freqs, total = compute_frequencies(np.frombuffer(data, dtype=np.uint8))
            intervals = build_intervals(freqs, total)

        with open(input_file, "rb") as f_in_encode, open(output_file, "wb") as f_out:
            current_low = 0.0
            current_high = 1.0
            total_bytes = os.path.getsize(input_file)
            bytes_processed = 0

            while True:
                chunk_bytes = f_in_encode.read(chunk_size)
                if not chunk_bytes:
                    break
                chunk_np = np.frombuffer(chunk_bytes, dtype=np.uint8)
                current_low, current_high = _encode_kernel(chunk_np, intervals, current_low, current_high)
                bytes_processed += len(chunk_bytes)
                if progress_callback:
                    progress_callback(bytes_processed / total_bytes * 100) # Процент выполнения

            f_out.write(struct.pack("I", np.count_nonzero(freqs)))
            for byte in range(256):
                if freqs[byte] > 0:
                    f_out.write(struct.pack("B", byte))
                    f_out.write(struct.pack("I", freqs[byte]))
            f_out.write(struct.pack("d", (current_low + current_high) / 2))

        return f"Сжатый файл записан: {output_file} (размер {os.path.getsize(output_file)} байт)"

    except Exception as e:
        return f"Ошибка сжатия: {e}"


@jit(nopython=True, parallel=False)
def _decode_kernel(freqs, total, intervals, encoded_value):
    """Ядро декодирования, оптимизированное Numba, с бинарным поиском."""
    result_np = np.empty(total, dtype=np.uint8)
    current_encoded_value = encoded_value

    interval_bytes = np.arange(256, dtype=np.int32)

    for i in range(total):
        l, r = 0, 256
        found_byte = -1
        while l < r:
            mid_index = (l + r) // 2
            byte_index = interval_bytes[mid_index]
            if freqs[byte_index] > 0 and intervals[byte_index, 0] <= current_encoded_value < intervals[byte_index, 1]:
                found_byte = byte_index
                break
            elif intervals[byte_index, 1] <= current_encoded_value:
                l = mid_index + 1
            else:
                r = mid_index

        if found_byte != -1:
            result_np[i] = found_byte
            current_encoded_value = (current_encoded_value - intervals[found_byte, 0]) / (intervals[found_byte, 1] - intervals[found_byte, 0])
        else:
            raise Exception("Байт не найден при декодировании!")

    return result_np

def decompress_file(input_file, output_file, progress_callback=None):
    """Распаковывает файл с арифметическим кодированием с прогресс-баром."""
    try:
        with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
            total_compressed_size = os.path.getsize(input_file)
            bytes_read = 0

            freqs_count = struct.unpack("I", f_in.read(4))[0]
            bytes_read += 4
            if progress_callback:
                progress_callback(bytes_read / total_compressed_size * 100)

            freqs = np.zeros(256, dtype=np.int32)
            for _ in range(freqs_count):
                byte = struct.unpack("B", f_in.read(1))[0]
                bytes_read += 1
                count = struct.unpack("I", f_in.read(4))[0]
                bytes_read += 4
                freqs[byte] = count
                if progress_callback:
                    progress_callback(bytes_read / total_compressed_size * 100)

            encoded_value = struct.unpack("d", f_in.read(8))[0]
            bytes_read += 8
            if progress_callback:
                progress_callback(bytes_read / total_compressed_size * 100)


            total = np.sum(freqs)
            intervals = build_intervals(freqs, total)
            result_np = _decode_kernel(freqs, total, intervals, encoded_value) # Само декодирование

            result_bytes = result_np.tobytes()
            f_out.write(result_bytes)

        return f"Разархивированный файл записан: {output_file} (размер {os.path.getsize(output_file)} байт)"

    except Exception as e:
        return f"Ошибка распаковки: {e}"


class ArithmeticCoderGUI:
    def __init__(self, root):
        self.root = root
        root.title("Арифметическое Сжатие/Распаковка")

        # Стиль интерфейса
        self.style = ttk.Style(root)
        self.style.theme_use('clam')

        # Шрифт
        self.default_font = font.Font(family="Helvetica", size=12)
        root.option_add("*Font", self.default_font)
        self.style.configure("TButton", padding=6, font=self.default_font)
        self.style.configure("TRadiobutton", padding=6, font=self.default_font)
        self.style.configure("TLabel", font=self.default_font)
        self.style.configure("TEntry", padding=6, font=self.default_font)
        self.style.configure("Horizontal.TProgressbar", thickness=10)

        # Режим работы
        self.mode = tk.StringVar(value="-c") # По умолчанию сжатие
        mode_frame = ttk.Frame(root, padding="10 10 12 12")
        mode_frame.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Radiobutton(mode_frame, text="Сжать", variable=self.mode, value="-c").grid(column=1, row=1, sticky=tk.W)
        ttk.Radiobutton(mode_frame, text="Распаковать", variable=self.mode, value="-d").grid(column=2, row=1, sticky=tk.W)

        # Входной файл
        self.input_file_path = tk.StringVar()
        input_frame = ttk.Frame(root, padding="10 10 12 12")
        input_frame.grid(column=0, row=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(input_frame, text="Входной файл:").grid(column=1, row=1, sticky=tk.W)
        input_entry = ttk.Entry(input_frame, width=40, textvariable=self.input_file_path)
        input_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))
        ttk.Button(input_frame, text="Обзор", command=self.browse_input_file).grid(column=3, row=1, sticky=tk.W)

        # Выходной файл
        self.output_file_path = tk.StringVar()
        output_frame = ttk.Frame(root, padding="10 10 12 12")
        output_frame.grid(column=0, row=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        ttk.Label(output_frame, text="Выходной файл:").grid(column=1, row=1, sticky=tk.W)
        output_entry = ttk.Entry(output_frame, width=40, textvariable=self.output_file_path)
        output_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))
        ttk.Button(output_frame, text="Обзор", command=self.browse_output_file).grid(column=3, row=1, sticky=tk.W)

        # Прогресс-бар
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=300, mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(column=0, row=3, pady=10, sticky=(tk.W, tk.E))

        # Кнопка действия
        self.action_button = ttk.Button(root, text="Старт", command=self.start_processing)
        self.action_button.grid(column=0, row=4, pady=10)

        # Статус
        self.status_text = tk.StringVar(value="Готов к работе")
        ttk.Label(root, textvariable=self.status_text).grid(column=0, row=5, pady=5)

        # Растягивание колонок и строк для корректного масштабирования
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=0)
        root.rowconfigure(1, weight=0)
        root.rowconfigure(2, weight=0)
        root.rowconfigure(3, weight=0)
        root.rowconfigure(4, weight=0)
        root.rowconfigure(5, weight=1)

        for child in mode_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)
        for child in input_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)
        for child in output_frame.winfo_children():
            child.grid_configure(padx=5, pady=5)


    def browse_input_file(self):
        filename = filedialog.askopenfilename()
        self.input_file_path.set(filename)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(defaultextension=".bin" if self.mode.get() == "-c" else ".txt")
        self.output_file_path.set(filename)

    def update_progress_bar(self, progress):
        self.progress_var.set(progress)
        self.root.update_idletasks()

    def start_processing(self):
        mode = self.mode.get()
        input_file = self.input_file_path.get()
        output_file = self.output_file_path.get()

        if not input_file or not output_file:
            self.status_text.set("Ошибка: Пожалуйста, выберите входной и выходной файлы.")
            return

        if not os.path.exists(input_file):
            self.status_text.set("Ошибка: Входной файл не существует.")
            return

        self.progress_var.set(0)
        self.status_text.set("Выполнение...")
        self.action_button.config(state=tk.DISABLED)

        try:
            if mode == "-c":
                result_message = compress_file(input_file, output_file, progress_callback=self.update_progress_bar)
            elif mode == "-d":
                result_message = decompress_file(input_file, output_file, progress_callback=self.update_progress_bar)
            else:
                result_message = "Ошибка: Неизвестный режим."

            self.status_text.set(result_message)

        except Exception as e:
            self.status_text.set(f"Произошла ошибка: {e}")
        finally:
            self.action_button.config(state=tk.NORMAL)


if __name__ == "__main__":
    print("Выполняем прогревочный запуск (с явными типами)...")
    dummy_data = np.array([0, 0, 0], dtype=np.uint8)
    dummy_freqs = np.zeros(256, dtype=np.int32)
    dummy_freqs[0] = 1
    dummy_total = np.int32(len(dummy_data))
    dummy_intervals = np.zeros((256, 2), dtype=np.float64)

    compute_frequencies(dummy_data)
    build_intervals(dummy_freqs, dummy_total)
    _encode_kernel(dummy_data, dummy_intervals, 0.0, 1.0)
    print("Прогревочный запуск завершен (с явными типами).\n")


    root = tk.Tk()
    gui = ArithmeticCoderGUI(root)
    root.mainloop()