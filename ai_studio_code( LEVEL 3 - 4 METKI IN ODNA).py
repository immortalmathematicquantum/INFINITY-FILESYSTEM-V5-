import os
import pickle
import json
import tkinter as tk
from tkinter import filedialog, messagebox
import datetime
import struct
import threading

# --- Глобальные константы ---
DATA_FILE = "data.pickle"
COMPRESSED_EXT = ".ctxt"
LOG_FILE = "compression_log.txt"

# Параметры алгоритма
# ИЗМЕНЕНО: Количество уровней сжатия
NUM_LEVELS = 3 
# ИЗМЕНЕНО: Длины хешей для 3-х уровней. Уровень 2 кодирует 4 элемента.
HASH_LENGTHS = {0: 1, 1: 1, 2: 4}
BASE_ALPHABET_STRING = (
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    'abcdefghijklmnopqrstuvwxyz'
    '0123456789'
    '一丁七万丈三上下不与丑专且世丘丙业丛东丝丞丢两严並丧丨'
    'अआइईउऊऋएऐओऔकखगघङचछजझञटठडढणतथदधनपफबभमयरलवशसह़ािीुूृॅेैॉोौ्ॐक़ख़ग़ज़ड़ढ़फ़य़'
    'ლვთსმნაბჩცძწჭხჯჰჱჲჳჴჵჶჷჸჹჺᏣᏤᏥᏦᏧᏨᏩᏪᏫᏬᏭᏮᏯ'
)
# Формируем алфавит из 256 уникальных символов
ALPHABET_SET = sorted(list(set(BASE_ALPHABET_STRING)))
if len(ALPHABET_SET) < 256:
    standard_chars = [chr(i) for i in range(256) if chr(i) not in ALPHABET_SET]
    ALPHABET_SET.extend(standard_chars)
FINAL_ALPHABET_LIST = ALPHABET_SET[:256]
FINAL_ALPHABET_STR = "".join(FINAL_ALPHABET_LIST)


BLOCKS_PER_BYTE = 4
PADDING_BLOCK_MULTIPLE = 16

ORIGINAL_LENGTH_HEADER_FORMAT = '>Q'
ORIGINAL_LENGTH_HEADER_SIZE = struct.calcsize(ORIGINAL_LENGTH_HEADER_FORMAT)

class Compressor:
    def __init__(self, alphabet_string):
        self.alphabet_list = list(alphabet_string)
        self.alphabet_map = {char: i for i, char in enumerate(self.alphabet_list)}
        self.base_len = len(self.alphabet_list)

        self.dictionaries = [{} for _ in range(NUM_LEVELS)]
        self.reverse_dictionaries = [{} for _ in range(NUM_LEVELS)]

    def _int_to_hash(self, n, level):
        if level not in HASH_LENGTHS:
            raise ValueError(f"Invalid level: {level}")
        length = HASH_LENGTHS[level]
        
        if n >= self.base_len ** length:
             raise ValueError(f"Number {n} (dict_len) is too large for hash length {length} at level {level} with base {self.base_len}.")

        hash_chars = []
        temp_n = n
        for _ in range(length):
            temp_n, rem = divmod(temp_n, self.base_len)
            hash_chars.append(self.alphabet_list[rem])
        
        if temp_n != 0:
            raise ValueError(f"Number {n} requires longer hash for level {level} than {length} chars.")
        return "".join(reversed(hash_chars))

    def _split_into_2bit_blocks(self, data: bytes):
        num_bytes = len(data)
        if num_bytes == 0:
            return []

        num_raw_blocks = num_bytes * BLOCKS_PER_BYTE
        total_blocks = ((num_raw_blocks + PADDING_BLOCK_MULTIPLE - 1) // PADDING_BLOCK_MULTIPLE) * PADDING_BLOCK_MULTIPLE
        if total_blocks == 0 and num_raw_blocks > 0 : total_blocks = PADDING_BLOCK_MULTIPLE

        blocks = bytearray(total_blocks)
        block_idx = 0
        for byte_val in data:
            blocks[block_idx]     = (byte_val >> 6) & 0x3
            blocks[block_idx + 1] = (byte_val >> 4) & 0x3
            blocks[block_idx + 2] = (byte_val >> 2) & 0x3
            blocks[block_idx + 3] =  byte_val       & 0x3
            block_idx += BLOCKS_PER_BYTE
        return list(blocks)

    def _combine_from_2bit_blocks(self, blocks: list):
        if not blocks:
            return bytearray()
        
        data_len = (len(blocks) // BLOCKS_PER_BYTE)
        combined_data = bytearray(data_len)
        for i in range(data_len):
            idx = i * BLOCKS_PER_BYTE
            if idx + 3 >= len(blocks):
                break 
            byte_val = (blocks[idx] << 6) | (blocks[idx+1] << 4) | \
                       (blocks[idx+2] << 2) | blocks[idx+3]
            combined_data[i] = byte_val
        return combined_data

    def compress_data(self, data: bytes) -> bytes:
        original_byte_length = len(data)
        current_data_elements = self._split_into_2bit_blocks(data)

        for level in range(NUM_LEVELS):
            new_data_elements = []
            if not current_data_elements:
                break
            
            # ИЗМЕНЕНО: Определяем размер группы в зависимости от уровня
            if level == 2:
                # УРОВЕНЬ 2: Объединяем по 4 элемента в 1
                step = 4
                group_size = 4
            else:
                # УРОВНИ 0, 1: Объединяем по 2 элемента в 1 (как было изначально)
                step = 2
                group_size = 2

            for i in range(0, len(current_data_elements), step):
                if i + (group_size - 1) >= len(current_data_elements):
                    # Если оставшихся элементов не хватает для полной группы, добавляем их как есть
                    new_data_elements.extend(current_data_elements[i:])
                    break

                group = tuple(current_data_elements[i : i + group_size])
                
                if group not in self.dictionaries[level]:
                    dict_len = len(self.dictionaries[level])
                    max_entries_for_hash_type = self.base_len ** HASH_LENGTHS[level]
                    if dict_len >= max_entries_for_hash_type :
                         raise OverflowError(
                             f"Dictionary for level {level} is full."
                         )

                    hash_code = self._int_to_hash(dict_len, level)
                    self.dictionaries[level][group] = hash_code
                    self.reverse_dictionaries[level][hash_code] = group
                
                new_data_elements.append(self.dictionaries[level][group])
            
            current_data_elements = new_data_elements

        final_hash_string = "".join(current_data_elements)
        
        try:
            payload_bytes = bytes([self.alphabet_map[char] for char in final_hash_string])
        except KeyError as e:
            raise ValueError(f"Symbol error during final conversion: char '{str(e)}' not in alphabet_map.") from e

        header_bytes = struct.pack(ORIGINAL_LENGTH_HEADER_FORMAT, original_byte_length)
        return header_bytes + payload_bytes

    def decompress_data(self, compressed_package: bytes) -> bytes:
        if len(compressed_package) < ORIGINAL_LENGTH_HEADER_SIZE:
            raise ValueError("Compressed data too short to contain header.")

        header_bytes = compressed_package[:ORIGINAL_LENGTH_HEADER_SIZE]
        payload_bytes = compressed_package[ORIGINAL_LENGTH_HEADER_SIZE:]
        
        original_byte_length = struct.unpack(ORIGINAL_LENGTH_HEADER_FORMAT, header_bytes)[0]

        if not payload_bytes and original_byte_length == 0:
            return b""
        if not payload_bytes and original_byte_length > 0:
            raise ValueError("Compressed payload is empty but original length > 0.")

        try:
            compressed_str = "".join([self.alphabet_list[byte_val] for byte_val in payload_bytes])
        except IndexError as e:
            raise ValueError(f"Invalid byte value in compressed data: {str(e)}") from e

        final_hash_len = HASH_LENGTHS[NUM_LEVELS - 1]
        
        # Обработка случая, когда финальные данные короче длины хеша (из-за неполных групп)
        if len(compressed_str) < final_hash_len:
             current_data_elements = [compressed_str]
        elif len(compressed_str) % final_hash_len != 0:
            # Если длина не кратна, возможно, есть остаток от неполной группы
            # Разбираем основную часть и добавляем остаток
            main_part_len = (len(compressed_str) // final_hash_len) * final_hash_len
            current_data_elements = [compressed_str[i : i + final_hash_len] 
                                     for i in range(0, main_part_len, final_hash_len)]
            remainder = compressed_str[main_part_len:]
            if remainder:
                current_data_elements.append(remainder) # Добавляем остаток как есть
        else:
            current_data_elements = [compressed_str[i : i + final_hash_len] 
                                     for i in range(0, len(compressed_str), final_hash_len)]


        for level in reversed(range(NUM_LEVELS)):
            if not current_data_elements:
                break
            
            rev_dict = self.reverse_dictionaries[level]
            new_data_elements = []
            for hash_code in current_data_elements:
                if hash_code in rev_dict:
                    new_data_elements.extend(rev_dict[hash_code])
                else:
                    # Если хеш-код не найден, это может быть неполный остаток с предыдущего уровня
                    # Просто пробрасываем его дальше
                    new_data_elements.append(hash_code)

            current_data_elements = new_data_elements
        
        raw_bytes = self._combine_from_2bit_blocks(current_data_elements)
        
        return raw_bytes[:original_byte_length]


def save_app_data(data_to_save):
    try:
        with open(DATA_FILE, 'wb') as f:
            pickle.dump(data_to_save, f)
    except Exception as e:
        messagebox.showerror("Error", f"Save error: {str(e)}")

def load_app_data():
    default_data = {
        "dictionaries": [{} for _ in range(NUM_LEVELS)],
        "reverse_dictionaries": [{} for _ in range(NUM_LEVELS)],
        "files": []
    }
    # ... (остальная часть функции без изменений)
    try:
        if os.path.exists("data.json"):
            with open("data.json", 'r', encoding='utf-8') as f:
                loaded_json_data = json.load(f)
            
            migrated_dictionaries = [
                {(tuple(k) if isinstance(k, list) else k): v for k, v in d.items()}
                for d in loaded_json_data.get("dictionary", [{} for _ in range(NUM_LEVELS)])
            ]
            migrated_reverse_dictionaries = [
                {v: k for k, v in d.items()} for d in migrated_dictionaries
            ]
            migrated_files = loaded_json_data.get("files", [])
            
            app_data = {
                "dictionaries": migrated_dictionaries,
                "reverse_dictionaries": migrated_reverse_dictionaries,
                "files": migrated_files
            }
            save_app_data(app_data)
            os.remove("data.json")
            messagebox.showinfo("Migration", "Data migrated from JSON to Pickle format.")
            return app_data

        elif os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'rb') as f:
                loaded_data = pickle.load(f)

            if "reverse_dictionaries" not in loaded_data or \
               len(loaded_data["reverse_dictionaries"]) != NUM_LEVELS or \
               any(not isinstance(d, dict) for d in loaded_data["reverse_dictionaries"]):
                
                messagebox.showwarning("Load Warning", "Reverse dictionaries missing or invalid. Rebuilding...")
                loaded_data["reverse_dictionaries"] = [
                    {v: k for k, v in d.items()} for d in loaded_data.get("dictionaries", default_data["dictionaries"])
                ]

            if "dictionaries" not in loaded_data or len(loaded_data["dictionaries"]) != NUM_LEVELS:
                 loaded_data["dictionaries"] = default_data["dictionaries"]
            if "files" not in loaded_data:
                 loaded_data["files"] = default_data["files"]

            return loaded_data
            
    except Exception as e:
        messagebox.showerror("Error", f"Load error: {str(e)}. Loading default data.")
    return default_data


def write_log(operation, filename, dictionaries):
    # ИЗМЕНЕНО: Теоретические максимумы для новой 3-уровневой логики
    max_pairs_theory = {
        0: 4**2,          # Уровень 0: Пары 2-битных блоков. 4*4=16
        1: (4**2)**2,     # Уровень 1: Пары хешей с ур0. 16*16=256
        2: ((4**2)**2)**4, # Уровень 2: Группы по 4 хеша с ур1. 256^4
    }
    
    log_entry = [
        f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {operation} '{filename}'"
    ]
    
    total_used = 0
    total_max_theoretical = sum(max_pairs_theory.values())
    
    for level in range(NUM_LEVELS): 
        count = len(dictionaries[level])
        total_used += count
        current_max = max_pairs_theory.get(level, 0)
        percent = (count / current_max * 100) if current_max > 0 else 0
        
        log_entry.append(
            f"Уровень {level}: {count:>10} / {current_max:<12} ({percent:.8f}%) "
            f"(Хеши: {HASH_LENGTHS[level]} симв.)"
        )
    
    total_percent = (total_used / total_max_theoretical * 100) if total_max_theoretical > 0 else 0
    log_entry.append(
        f"Итого:     {total_used:>10} / {total_max_theoretical:<12} ({total_percent:.10f}%)"
    )
    log_entry.append("-" * 70) 
    
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write("\n".join(log_entry) + "\n\n")
    except Exception as e:
        print(f"Error writing log: {e}")


class FileManager:
    # ... (вся остальная часть кода без изменений)
    def __init__(self, root_window):
        self.root = root_window
        self.root.title("3-Level Compressor (4-to-1 final)")
        
        self.app_state = load_app_data()
        
        self.compressor = Compressor(FINAL_ALPHABET_STR)
        self.compressor.dictionaries = self.app_state["dictionaries"]
        self.compressor.reverse_dictionaries = self.app_state["reverse_dictionaries"]

        self.listbox = tk.Listbox(self.root, font=('Courier', 10), width=80)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.btn_frame = tk.Frame(self.root)
        self.btn_frame.pack(fill=tk.X, padx=5, pady=5)

        self.compress_btn = tk.Button(self.btn_frame, text="Compress", command=self.compress_file_threaded, width=12)
        self.compress_btn.pack(side=tk.LEFT, padx=2)
        
        self.decompress_btn = tk.Button(self.btn_frame, text="Decompress", command=self.decompress_file_threaded, width=12)
        self.decompress_btn.pack(side=tk.RIGHT, padx=2)

        self.update_list()

    def _toggle_buttons(self, enable):
        state = tk.NORMAL if enable else tk.DISABLED
        self.compress_btn.config(state=state)
        self.decompress_btn.config(state=state)

    def update_list(self):
        self.listbox.delete(0, tk.END)
        for fname in self.app_state["files"]:
            self.listbox.insert(tk.END, fname)

    def _run_operation_in_thread(self, operation_func, *args):
        self._toggle_buttons(False)
        thread = threading.Thread(target=operation_func, args=args, daemon=True)
        thread.start()

    def compress_file_threaded(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        self._run_operation_in_thread(self._compress_file_task, path)

    def _compress_file_task(self, path):
        try:
            with open(path, 'rb') as f:
                data = f.read()
            
            compressed_package = self.compressor.compress_data(data)
            
            base_filename = os.path.basename(path)
            output_name = base_filename + COMPRESSED_EXT
            
            with open(output_name, 'wb') as f:
                f.write(compressed_package)
            
            def Succeeded():
                if output_name not in self.app_state["files"]:
                    self.app_state["files"].append(output_name)
                
                self.app_state["dictionaries"] = self.compressor.dictionaries
                self.app_state["reverse_dictionaries"] = self.compressor.reverse_dictionaries
                save_app_data(self.app_state)
                self.update_list()
                write_log("СЖАТИЕ", base_filename, self.compressor.dictionaries)
                messagebox.showinfo("Success", f"File '{base_filename}' compressed successfully to '{output_name}'!")
                self._toggle_buttons(True)

            self.root.after(0, Succeeded)

        except Exception as e:
            error_message = f"Compression failed for '{os.path.basename(path)}': {str(e)}"
            print(error_message)
            self.root.after(0, lambda: (
                messagebox.showerror("Error", error_message),
                self._toggle_buttons(True)
            ))


    def decompress_file_threaded(self):
        selected_idx = self.listbox.curselection()
        if not selected_idx:
            messagebox.showwarning("Selection", "No file selected for decompression.")
            return
        selected_file = self.listbox.get(selected_idx[0])
        
        default_savename = selected_file.replace(COMPRESSED_EXT, "")
        if default_savename == selected_file:
            default_savename += ".decompressed"

        save_path = filedialog.asksaveasfilename(
            defaultextension=".bin",
            initialfile=default_savename
        )
        if not save_path:
            return

        self._run_operation_in_thread(self._decompress_file_task, selected_file, save_path)


    def _decompress_file_task(self, compressed_file_path, save_path):
        try:
            with open(compressed_file_path, 'rb') as f:
                compressed_package = f.read()
            
            decompressed_data = self.compressor.decompress_data(compressed_package)
            
            with open(save_path, 'wb') as f:
                f.write(decompressed_data)
            
            def Succeeded():
                write_log("РАСПАКОВКА", os.path.basename(compressed_file_path), self.compressor.dictionaries)
                messagebox.showinfo("Success", f"File '{os.path.basename(compressed_file_path)}' decompressed successfully to '{os.path.basename(save_path)}'!")
                self._toggle_buttons(True)
            
            self.root.after(0, Succeeded)

        except Exception as e:
            error_message = f"Decompression failed for '{os.path.basename(compressed_file_path)}': {str(e)}"
            print(error_message)
            self.root.after(0, lambda: (
                messagebox.showerror("Error", error_message),
                self._toggle_buttons(True)
            ))


if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("700x450")
    app = FileManager(root)
    root.mainloop()