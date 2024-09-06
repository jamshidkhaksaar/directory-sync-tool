import os
import hashlib
import shutil
import logging
import re
import configparser
import argparse
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, messagebox
import threading
from tkinter import font as tkfont

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to calculate SHA1 hash of a file
def calculate_sha1(file_path):
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(65536)  # Read in chunks of 64KB
                if not data:
                    break
                sha1.update(data)
        return sha1.hexdigest()
    except IOError as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None

# Function to compare two files by modification time and SHA1 hash
def compare_files(file1, file2):
    try:
        mod_time1 = os.path.getmtime(file1)
        mod_time2 = os.path.getmtime(file2)

        if mod_time1 != mod_time2:
            return False

        sha1_file1 = calculate_sha1(file1)
        sha1_file2 = calculate_sha1(file2)

        return sha1_file1 == sha1_file2
    except Exception as e:
        logging.error(f"Error comparing files {file1} and {file2}: {e}")
        return False

# Function to get the total size of files
def get_total_size(file_list):
    total_size = 0
    for file in file_list:
        try:
            total_size += os.path.getsize(file)
        except FileNotFoundError:
            logging.warning(f"File not found: {file}")
    return total_size

# Function to compare directories and prepare sync/removal lists
def compare_directories(source_dir, dest_dir, progress_var, log_widgets):
    files_to_sync = []
    files_to_remove = []
    folders_to_remove = []

    logging.info("Comparing files between source and destination...")

    total_files = sum(len(files) for _, _, files in os.walk(source_dir))
    if progress_var:
        progress_var.set(0)
    current_progress = 0

    for dirpath, dirnames, filenames in os.walk(source_dir):
        rel_path = os.path.relpath(dirpath, source_dir)
        dest_subdir = os.path.join(dest_dir, rel_path)

        for file_name in filenames:
            source_file = os.path.join(dirpath, file_name)
            dest_file = os.path.join(dest_subdir, file_name)

            if not os.path.exists(dest_file):
                files_to_sync.append((source_file, dest_file, "Copy"))
                log_widgets['Source'].insert(tk.END, f"New: {source_file}\n", "new")
                log_widgets['Source'].see(tk.END)
            else:
                if not compare_files(source_file, dest_file):
                    files_to_sync.append((source_file, dest_file, "Update"))
                    log_widgets['Source'].insert(tk.END, f"Update: {source_file}\n", "update")
                    log_widgets['Source'].see(tk.END)
                else:
                    log_widgets['Destination'].insert(tk.END, f"Duplicate: {dest_file}\n", "duplicate")
                    log_widgets['Destination'].see(tk.END)

            current_progress += 1
            if progress_var:
                progress_var.set((current_progress / total_files) * 100)

        for dirname in dirnames:
            source_folder = os.path.join(dirpath, dirname)
            dest_folder = os.path.join(dest_subdir, dirname)

            if not os.path.exists(dest_folder):
                log_widgets['Source'].insert(tk.END, f"New Folder: {source_folder}\n", "new_folder")
                log_widgets['Source'].see(tk.END)
            else:
                log_widgets['Destination'].insert(tk.END, f"Duplicate Folder: {dest_folder}\n", "duplicate_folder")
                log_widgets['Destination'].see(tk.END)

    for dirpath, dirnames, filenames in os.walk(dest_dir):
        rel_path = os.path.relpath(dirpath, dest_dir)
        source_subdir = os.path.join(source_dir, rel_path)

        if not os.path.exists(source_subdir):
            for file_name in filenames:
                dest_file = os.path.join(dirpath, file_name)
                files_to_remove.append(dest_file)
                log_widgets['Destination'].insert(tk.END, f"Remove: {dest_file}\n", "remove")
                log_widgets['Destination'].see(tk.END)
            folders_to_remove.append(dirpath)
            log_widgets['Destination'].insert(tk.END, f"Remove Folder: {dirpath}\n", "remove_folder")
            log_widgets['Destination'].see(tk.END)
        else:
            for file_name in filenames:
                dest_file = os.path.join(dirpath, file_name)
                source_file = os.path.join(source_subdir, file_name)
                if not os.path.exists(source_file):
                    files_to_remove.append(dest_file)
                    log_widgets['Destination'].insert(tk.END, f"Remove: {dest_file}\n", "remove")
                    log_widgets['Destination'].see(tk.END)

    return files_to_sync, files_to_remove, folders_to_remove

# Function to perform sync operations
def perform_sync(files_to_sync, files_to_remove, folders_to_remove, progress_var, log_widgets):
    total_operations = len(files_to_sync) + len(files_to_remove) + len(folders_to_remove)
    progress_var.set(0)

    for source_file, dest_file, action in files_to_sync:
        try:
            dest_subdir = os.path.dirname(dest_file)
            if not os.path.exists(dest_subdir):
                os.makedirs(dest_subdir)
            shutil.copy2(source_file, dest_file)
            logging.info(f"{action}: {source_file} -> {dest_file}")
            log_widgets['Source'].insert(tk.END, f"{action}: {source_file}\n", "sync")
            log_widgets['Source'].see(tk.END)
            log_widgets['Destination'].insert(tk.END, f"{action}: {dest_file}\n", "sync")
            log_widgets['Destination'].see(tk.END)
        except Exception as e:
            logging.error(f"Error during {action} of {source_file}: {e}")
        progress_var.set(min(100, progress_var.get() + 1 / total_operations * 100))

    total_remove_size = get_total_size(files_to_remove)

    for file in files_to_remove:
        try:
            os.remove(file)
            logging.info(f"Removed: {file}")
            log_widgets['Destination'].insert(tk.END, f"Removed: {file}\n", "remove")
            log_widgets['Destination'].see(tk.END)
        except Exception as e:
            logging.error(f"Failed to remove file {file}: {e}")
        progress_var.set(progress_var.get() + 1 / total_operations * 100)

    for folder in sorted(folders_to_remove, reverse=True):
        try:
            os.rmdir(folder)
            logging.info(f"Removed folder: {folder}")
            log_widgets['Destination'].insert(tk.END, f"Removed folder: {folder}\n", "remove_folder")
            log_widgets['Destination'].see(tk.END)
        except OSError as e:
            logging.error(f"Failed to remove folder {folder}: {e}")
        progress_var.set(progress_var.get() + 1 / total_operations * 100)

    # Ensure progress bar reaches 100%
    progress_var.set(100)

    return total_remove_size

# Email notification function using SendGrid
def send_notification(files_synced, sync_size, files_removed, remove_size, folders_removed):
    config = configparser.ConfigParser()
    config.read('config.ini')

    from_email = config.get('Email', 'from_email', fallback=None)
    to_email = config.get('Email', 'to_email', fallback=None)
    subject = "Sync Completed Notification"
    body = f"""
    Sync Completed Summary:
    Total files synced (copy/update): {files_synced}
    Total size of files synced: {sync_size / (1024 * 1024):.2f} MB
    Total files removed: {files_removed}
    Total size of files removed: {remove_size / (1024 * 1024):.2f} MB
    Total folders removed: {folders_removed}
    """

    if not from_email or not to_email:
        logging.error("Missing 'from_email' or 'to_email' in the config.ini")
        return

    message = Mail(
        from_email=from_email,
        to_emails=to_email,
        subject=subject,
        plain_text_content=body
    )

    try:
        sg = SendGridAPIClient(config['SendGrid']['API_KEY'])
        response = sg.send(message)
        logging.info(f"Notification email sent successfully. Status code: {response.status_code}")
    except Exception as e:
        logging.error(f"Failed to send notification email: {e}")

# Directory validation
def validate_directory(path):
    if not os.path.isdir(path):
        raise ValueError(f"Invalid directory path: {path}")

# Email validation using regex
def validate_email(email):
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise ValueError(f"Invalid email address: {email}")

# Main function using argparse
def main(source_dir=None, dest_dir=None, display_only=False, progress_var=None, log_widgets=None):
    if source_dir is None or dest_dir is None:
        parser = argparse.ArgumentParser(description="Directory Synchronization Script")
        parser.add_argument("source_dir", help="Source directory to sync from")
        parser.add_argument("dest_dir", help="Destination directory to sync to")
        parser.add_argument("--display-only", action="store_true", help="Display sync information without performing actual sync")

        args = parser.parse_args()

        source_dir = args.source_dir
        dest_dir = args.dest_dir
        display_only = args.display_only

    logging.debug(f"Source directory: {source_dir}")
    logging.debug(f"Destination directory: {dest_dir}")

    validate_directory(source_dir)
    validate_directory(dest_dir)

    # Ensure source and destination directories are not the same
    if os.path.abspath(source_dir) == os.path.abspath(dest_dir):
        raise ValueError("Source and destination directories cannot be the same.")

    # Sync directories including subfolders
    files_to_sync, files_to_remove, folders_to_remove = compare_directories(source_dir, dest_dir, progress_var, log_widgets)

    logging.info(f"\nSummary:")
    logging.info(f"Total files to sync (copy/update): {len(files_to_sync)}")
    logging.info(f"Total files to remove: {len(files_to_remove)}")

    if not display_only:
        total_remove_size = perform_sync(files_to_sync, files_to_remove, folders_to_remove, progress_var, log_widgets)
    else:
        logging.info("Display mode only. No synchronization or removal will be performed.")
        total_remove_size = get_total_size(files_to_remove)

    total_sync_size = get_total_size([file[0] for file in files_to_sync])

    logging.info(f"Total size of files synced: {total_sync_size / (1024 * 1024):.2f} MB")
    logging.info(f"Total size of files removed: {total_remove_size / (1024 * 1024):.2f} MB")
    logging.info(f"Total folders removed: {len(folders_to_remove)}")

    if not display_only:
        # Send notification only once at the end
        send_notification(len(files_to_sync), total_sync_size, len(files_to_remove), total_remove_size, len(folders_to_remove))

    return len(files_to_sync), total_sync_size, len(files_to_remove), total_remove_size, len(folders_to_remove)

# GUI functions
def browse_source():
    source_dir = filedialog.askdirectory()
    source_entry.delete(0, tk.END)
    source_entry.insert(0, source_dir)

def browse_dest():
    dest_dir = filedialog.askdirectory()
    dest_entry.delete(0, tk.END)
    dest_entry.insert(0, dest_dir)

def sync_directories():
    global sync_thread
    source_dir = source_entry.get()
    dest_dir = dest_entry.get()
    display_only = False  # Always perform the sync

    try:
        sync_thread = threading.Thread(target=sync_thread_func, args=(source_dir, dest_dir, display_only, log_widgets))
        sync_thread.start()
        update_status("Sync in progress")
        cancel_button.config(state=tk.NORMAL)
    except Exception as e:
        tk.messagebox.showerror("Error", f"An error occurred: {e}")

def sync_thread_func(source_dir, dest_dir, display_only, log_widgets):
    global files_synced, sync_size, files_removed, remove_size, folders_removed
    files_synced, sync_size, files_removed, remove_size, folders_removed = main(source_dir, dest_dir, display_only, progress_var, log_widgets)
    root.after(0, update_summary)
    update_status("Sync completed")
    cancel_button.config(state=tk.DISABLED)

def update_summary():
    summary_text.set(f"Summary:\nTotal files synced (copy/update): {files_synced}\nTotal size of files synced: {sync_size / (1024 * 1024):.2f} MB\nTotal files removed: {files_removed}\nTotal size of files removed: {remove_size / (1024 * 1024):.2f} MB\nTotal folders removed: {folders_removed}")

def clear_logs():
    for log_widget in log_widgets.values():
        log_widget.delete(1.0, tk.END)

def save_logs():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as f:
            for log_widget in log_widgets.values():
                f.write(log_widget.get(1.0, tk.END))

def open_settings():
    settings_window = tk.Toplevel(root)
    settings_window.title("Settings")

    from_email_label = tk.Label(settings_window, text="From Email:")
    from_email_label.grid(row=0, column=0, padx=10, pady=10)
    from_email_entry = tk.Entry(settings_window, width=50)
    from_email_entry.grid(row=0, column=1, padx=10, pady=10)

    to_email_label = tk.Label(settings_window, text="To Email:")
    to_email_label.grid(row=1, column=0, padx=10, pady=10)
    to_email_entry = tk.Entry(settings_window, width=50)
    to_email_entry.grid(row=1, column=1, padx=10, pady=10)

    api_key_label = tk.Label(settings_window, text="SendGrid API Key:")
    api_key_label.grid(row=2, column=0, padx=10, pady=10)
    api_key_entry = tk.Entry(settings_window, width=50)
    api_key_entry.grid(row=2, column=1, padx=10, pady=10)

    def save_settings():
        config = configparser.ConfigParser()
        config['Email'] = {
            'from_email': from_email_entry.get(),
            'to_email': to_email_entry.get()
        }
        config['SendGrid'] = {
            'API_KEY': api_key_entry.get()
        }
        with open('config.ini', 'w') as configfile:
            config.write(configfile)
        settings_window.destroy()

    save_button = tk.Button(settings_window, text="Save", command=save_settings)
    save_button.grid(row=3, column=0, columnspan=2, pady=10)

def open_help():
    help_text = """
    Directory Synchronization Tool Help

    1. Enter the source and destination directories.
    2. Click "Compare" to see the differences between the source and destination directories.
    3. Click "Sync Directories" to start the sync process.
    4. Use the "Clear Logs" button to clear the log window.
    5. Use the "Save Logs" button to save the logs to a file.
    6. Use the "Settings" button to configure email settings.
    7. The summary will be displayed after the sync process completes.
    """
    messagebox.showinfo("Help", help_text)

def update_status(status):
    status_var.set(status)

def cancel_sync():
    global cancel_flag
    cancel_flag = True
    update_status("Sync Cancelled")
    cancel_button.config(state=tk.DISABLED)

def refresh_directories():
    source_dir = source_entry.get()
    dest_dir = dest_entry.get()
    try:
        validate_directory(source_dir)
        validate_directory(dest_dir)
        update_status("Directories refreshed")
    except ValueError as e:
        update_status(str(e))

def compare_directories_gui():
    source_dir = source_entry.get()
    dest_dir = dest_entry.get()
    display_only = True

    try:
        compare_thread = threading.Thread(target=compare_thread_func, args=(source_dir, dest_dir, display_only, log_widgets))
        compare_thread.start()
        update_status("Comparing directories")
    except Exception as e:
        tk.messagebox.showerror("Error", f"An error occurred: {e}")

def compare_thread_func(source_dir, dest_dir, display_only, log_widgets):
    global files_synced, sync_size, files_removed, remove_size, folders_removed
    files_synced, sync_size, files_removed, remove_size, folders_removed = main(source_dir, dest_dir, display_only, progress_var, log_widgets)
    root.after(0, update_summary)
    update_status("Comparison completed")

# Create the main window
root = tk.Tk()
root.title("Directory Synchronization")
root.geometry("800x600")

# Modern font
modern_font = tkfont.Font(family="Helvetica", size=12)

# Color scheme
bg_color = "#f0f0f0"
button_color = "#4CAF50"
text_color = "#333333"

# Set background color
root.configure(bg=bg_color)

# Create and place widgets
source_label = tk.Label(root, text="Source Directory:", font=modern_font, bg=bg_color, fg=text_color)
source_label.grid(row=0, column=0, padx=10, pady=10)
source_entry = tk.Entry(root, width=50, font=modern_font)
source_entry.grid(row=0, column=1, padx=10, pady=10)
source_button = tk.Button(root, text="Browse", command=browse_source, font=modern_font, bg=button_color, fg="white")
source_button.grid(row=0, column=2, padx=10, pady=10)

dest_label = tk.Label(root, text="Destination Directory:", font=modern_font, bg=bg_color, fg=text_color)
dest_label.grid(row=1, column=0, padx=10, pady=10)
dest_entry = tk.Entry(root, width=50, font=modern_font)
dest_entry.grid(row=1, column=1, padx=10, pady=10)
dest_button = tk.Button(root, text="Browse", command=browse_dest, font=modern_font, bg=button_color, fg="white")
dest_button.grid(row=1, column=2, padx=10, pady=10)

compare_button = tk.Button(root, text="Compare", command=compare_directories_gui, font=modern_font, bg=button_color, fg="white")
compare_button.grid(row=2, column=0, columnspan=3, pady=10)

sync_button = tk.Button(root, text="Sync Directories", command=sync_directories, font=modern_font, bg=button_color, fg="white")
sync_button.grid(row=3, column=0, columnspan=3, pady=10)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.grid(row=4, column=0, columnspan=3, pady=10)

percentage_label = tk.Label(root, text="0%", font=modern_font, bg=bg_color, fg=text_color)
percentage_label.grid(row=5, column=0, columnspan=3, pady=10)

# Create paned window for log views
paned_window = tk.PanedWindow(root, orient=tk.HORIZONTAL)
paned_window.grid(row=6, column=0, columnspan=3, pady=10)

# Create separate log views
log_widgets = {}
log_widgets['Source'] = scrolledtext.ScrolledText(paned_window, height=10, width=80, font=modern_font)
log_widgets['Destination'] = scrolledtext.ScrolledText(paned_window, height=10, width=80, font=modern_font)

# Configure tags for different log types
log_widgets['Source'].tag_config("new", foreground="green")
log_widgets['Source'].tag_config("update", foreground="blue")
log_widgets['Source'].tag_config("new_folder", foreground="purple")
log_widgets['Destination'].tag_config("duplicate", foreground="orange")
log_widgets['Destination'].tag_config("duplicate_folder", foreground="orange")
log_widgets['Destination'].tag_config("remove", foreground="red")
log_widgets['Destination'].tag_config("remove_folder", foreground="red")
log_widgets['Source'].tag_config("sync", foreground="black")
log_widgets['Destination'].tag_config("sync", foreground="black")

paned_window.add(log_widgets['Source'])
paned_window.add(log_widgets['Destination'])

clear_logs_button = tk.Button(root, text="Clear Logs", command=clear_logs, font=modern_font, bg=button_color, fg="white")
clear_logs_button.grid(row=7, column=0, padx=10, pady=10)

save_logs_button = tk.Button(root, text="Save Logs", command=save_logs, font=modern_font, bg=button_color, fg="white")
save_logs_button.grid(row=7, column=1, padx=10, pady=10)

settings_button = tk.Button(root, text="Settings", command=open_settings, font=modern_font, bg=button_color, fg="white")
settings_button.grid(row=7, column=2, padx=10, pady=10)

help_button = tk.Button(root, text="Help", command=open_help, font=modern_font, bg=button_color, fg="white")
help_button.grid(row=8, column=0, columnspan=3, pady=10)

summary_text = tk.StringVar()
summary_label = tk.Label(root, textvariable=summary_text, font=modern_font, bg=bg_color, fg=text_color)
summary_label.grid(row=9, column=0, columnspan=3, pady=10)

status_var = tk.StringVar()
status_var.set("Idle")
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W, font=modern_font, bg=bg_color, fg=text_color)
status_bar.grid(row=10, column=0, columnspan=3, sticky=tk.W+tk.E)

cancel_button = tk.Button(root, text="Cancel Sync", command=cancel_sync, state=tk.DISABLED, font=modern_font, bg=button_color, fg="white")
cancel_button.grid(row=11, column=0, columnspan=3, pady=10)

refresh_button = tk.Button(root, text="Refresh Directories", command=refresh_directories, font=modern_font, bg=button_color, fg="white")
refresh_button.grid(row=12, column=0, columnspan=3, pady=10)

# Update the percentage label
def update_percentage():
    percentage = int(progress_var.get())
    percentage_label.config(text=f"{percentage}%")
    root.after(100, update_percentage)

# Start updating the percentage label
update_percentage()

# Start the main loop
root.mainloop()

# Add these global variable declarations at the beginning of the script
files_synced = 0
sync_size = 0
files_removed = 0
remove_size = 0
folders_removed = 0
cancel_flag = False
sync_thread = None