import os
import struct
import numpy as np
from numba import jit
import time
from tkinter import Tk
from tkinter.filedialog import askopenfilename, asksaveasfilename

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

def compress(input_file, output_file, chunk_size=1024*1024):
    """Сжимает файл с арифметическим кодированием, обрабатывая чанками."""
    with open(input_file, "rb") as f_in_freqs:
        data = f_in_freqs.read()
        if not data:
            print("Ошибка: входной файл пуст!")
            return

        freqs, total = compute_frequencies(np.frombuffer(data, dtype=np.uint8))
        intervals = build_intervals(freqs, total)

    with open(input_file, "rb") as f_in_encode, open(output_file, "wb") as f_out:
        current_low = 0.0
        current_high = 1.0

        while True:
            chunk_bytes = f_in_encode.read(chunk_size)
            if not chunk_bytes:
                break
            chunk_np = np.frombuffer(chunk_bytes, dtype=np.uint8)
            current_low, current_high = _encode_kernel(chunk_np, intervals, current_low, current_high)

        f_out.write(struct.pack("I", np.count_nonzero(freqs)))
        for byte in range(256):
            if freqs[byte] > 0:
                f_out.write(struct.pack("B", byte))
                f_out.write(struct.pack("I", freqs[byte]))
        f_out.write(struct.pack("d", (current_low + current_high) / 2))

    print(f"\nСжатый файл записан: {output_file} (размер {os.path.getsize(output_file)} байт)")
    
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

def decompress(input_file, output_file):
    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        freqs_count = struct.unpack("I", f_in.read(4))[0]
        freqs = np.zeros(256, dtype=np.int32)
        for _ in range(freqs_count):
            byte = struct.unpack("B", f_in.read(1))[0]
            count = struct.unpack("I", f_in.read(4))[0]
            freqs[byte] = count
        encoded_value = struct.unpack("d", f_in.read(8))[0]
        total = np.sum(freqs)
        intervals = build_intervals(freqs, total)
        result_np = _decode_kernel(freqs, total, intervals, encoded_value)

        result_bytes = result_np.tobytes()
        f_out.write(result_bytes)

        print(f"\nРазархивированный файл записан: {output_file} (размер {os.path.getsize(output_file)} байт)")

if __name__ == "__main__":
    import sys

    if len(sys.argv) == 1:
        print("Выберите режим:")
        print("  Сжатие: введите 'c'")
        print("  Распаковка: введите 'd'")
        mode = input("Режим: ")

        if mode not in ('c', 'd'):
            print("Ошибка: неверный режим. Используйте 'c' для сжатия и 'd' для распаковки.")
            sys.exit(1)

        Tk().withdraw()  # Скрыть главное окно tkinter
        if mode == 'c':
            input_file = askopenfilename(title="Выберите файл для сжатия")
            output_file = asksaveasfilename(title="Сохранить сжатый файл как", defaultextension=".bin")
        elif mode == 'd':
            input_file = askopenfilename(title="Выберите файл для распаковки")
            output_file = asksaveasfilename(title="Сохранить распакованный файл как", defaultextension="")
    elif len(sys.argv) == 4:
        mode, input_file, output_file = sys.argv[1:4]
        if mode == "-c":
            mode = 'c'
        elif mode == "-d":
            mode = 'd'
        else:
            print("Использование:")
            print("  Сжатие: python cc.py -c input.txt output.bin")
            print("  Распаковка: python cc.py -d input.bin output.txt")
            sys.exit(1)
    else:
        print("Использование:")
        print("  Сжатие: python cc.py -c input.txt output.bin")
        print("  Распаковка: python cc.py -d input.bin output.txt")
        sys.exit(1)

    print("Выполняем прогревочный запуск (с явными типами)...")
    dummy_data = np.array([0, 0, 0], dtype=np.uint8) # Явный тип uint8
    dummy_freqs = np.zeros(256, dtype=np.int32) # Явный тип int32
    dummy_freqs[0] = 1  # <----  Исправление: задаем частоту для байта 0
    dummy_total = np.int32(len(dummy_data)) # Явный тип int32 для total
    dummy_intervals = np.zeros((256, 2), dtype=np.float64) # Явный тип float64

    compute_frequencies(dummy_data) # Прогрев compute_frequencies
    build_intervals(dummy_freqs, dummy_total) # Прогрев build_intervals
    _encode_kernel(dummy_data, dummy_intervals, 0.0, 1.0) # Прогрев _encode_kernel
    print("Прогревочный запуск завершен (с явными типами).\n")

    if mode == "c":
        start_time = time.time()
        compress(input_file, output_file)
        end_time = time.time()
        print(f"Время сжатия: {end_time - start_time:.4f} секунд")

    elif mode == "d":
        start_time = time.time()
        decompress(input_file, output_file)
        end_time = time.time()
        print(f"Время распаковки: {end_time - start_time:.4f} секунд")

    elif mode == "-c":
        start_time = time.time()
        compress(input_file, output_file)
        end_time = time.time()
        print(f"Время заспаковки: {end_time - start_time:.4f} секунд")

    elif mode == "-d":
        start_time = time.time()
        decompress(input_file, output_file)
        end_time = time.time()
        print(f"Время распаковки: {end_time - start_time:.4f} секунд")

    else:
        print("Ошибка: неизвестный режим! Используйте -c (сжатие) или -d (распаковка).")