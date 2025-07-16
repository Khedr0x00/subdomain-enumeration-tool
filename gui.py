import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import requests
import os
import re
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import shutil

class SubdomainTool:
    def __init__(self, master):
        self.master = master
        master.title("Subdomain Enumeration Tool")
        master.geometry("800x700")
        master.resizable(True, True)

        # Create a main frame to hold all widgets for better layout management
        self.main_frame = tk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10) # Pack to fill the root window

        # Configure grid for responsiveness on the main_frame
        # Corrected method names: grid_rowconfigure and grid_columnconfigure (removed underscore before configure)
        self.main_frame.grid_rowconfigure(0, weight=0)
        self.main_frame.grid_rowconfigure(1, weight=0)
        self.main_frame.grid_rowconfigure(2, weight=0) # Button frame
        self.main_frame.grid_rowconfigure(3, weight=0) # Status label
        self.main_frame.grid_rowconfigure(4, weight=1) # Text area will expand
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        self.temp_dir = "temp_kaeferjaeger_certs"
        # Ensure the temporary directory exists
        os.makedirs(self.temp_dir, exist_ok=True)

        # Domain Input - now placed in self.main_frame
        self.domain_label = tk.Label(self.main_frame, text="Target Domain (e.g., example.com):", font=("Arial", 10))
        self.domain_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.domain_entry = tk.Entry(self.main_frame, width=50, font=("Arial", 10))
        self.domain_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        # Shodan API Key Input - now placed in self.main_frame
        self.shodan_label = tk.Label(self.main_frame, text="Shodan API Key:", font=("Arial", 10))
        self.shodan_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.shodan_entry = tk.Entry(self.main_frame, width=50, show="*", font=("Arial", 10)) # Show * for password-like input
        self.shodan_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        # Buttons Frame - now placed in self.main_frame
        self.button_frame = tk.Frame(self.main_frame)
        self.button_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")
        self.button_frame.grid_columnconfigure(0, weight=1)
        self.button_frame.grid_columnconfigure(1, weight=1)
        self.button_frame.grid_columnconfigure(2, weight=1)
        self.button_frame.grid_columnconfigure(3, weight=1)

        self.kaeferjaeger_button = tk.Button(self.button_frame, text="Download & Process Kaeferjaeger Data", command=self.process_kaeferjaeger_data, font=("Arial", 10), bg="#4CAF50", fg="white", relief="raised", bd=3)
        self.kaeferjaeger_button.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

        self.shodan_button = tk.Button(self.button_frame, text="Fetch Subdomains via Shodan", command=self.fetch_shodan_subdomains, font=("Arial", 10), bg="#2196F3", fg="white", relief="raised", bd=3)
        self.shodan_button.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.clear_button = tk.Button(self.button_frame, text="Clear Results", command=self.clear_results, font=("Arial", 10), bg="#f44336", fg="white", relief="raised", bd=3)
        self.clear_button.grid(row=0, column=2, padx=5, pady=5, sticky="ew")

        self.save_button = tk.Button(self.button_frame, text="Save Results", command=self.save_results, font=("Arial", 10), bg="#FFC107", fg="black", relief="raised", bd=3)
        self.save_button.grid(row=0, column=3, padx=5, pady=5, sticky="ew")

        # Status Label - now placed in self.main_frame
        self.status_label = tk.Label(self.main_frame, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, font=("Arial", 10))
        self.status_label.grid(row=3, column=0, columnspan=2, sticky="ew", padx=5, pady=5)

        # Results Text Area - now placed in self.main_frame
        self.results_text = scrolledtext.ScrolledText(self.main_frame, wrap=tk.WORD, width=80, height=20, font=("Arial", 10), bg="#f0f0f0", fg="#333333")
        self.results_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.main_frame.grid_rowconfigure(4, weight=1) # Make results text area expandable within main_frame

    def update_status(self, message):
        """Updates the status bar message."""
        self.status_label.config(text=f"Status: {message}")
        self.master.update_idletasks() # Force GUI update

    def append_result(self, text):
        """Appends text to the results text area and scrolls to the end."""
        self.results_text.insert(tk.END, text + "\n")
        self.results_text.see(tk.END) # Scroll to the end

    def clear_results(self):
        """Clears the results text area."""
        self.results_text.delete(1.0, tk.END)
        self.update_status("Results cleared.")

    def save_results(self):
        """Saves the content of the results text area to a file."""
        results = self.results_text.get(1.0, tk.END).strip()
        if not results:
            messagebox.showinfo("No Results", "No results to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Subdomains"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(results)
                messagebox.showinfo("Saved", f"Results saved to: {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"An error occurred while saving the file: {e}")

    def process_kaeferjaeger_data(self):
        """Initiates the process of downloading and parsing Kaeferjaeger data."""
        target_domain = self.domain_entry.get().strip()
        if not target_domain:
            messagebox.showwarning("Missing Input", "Please enter the target domain.")
            return

        self.update_status("Starting Kaeferjaeger data processing...")
        self.append_result(f"--- Starting Kaeferjaeger data search for: {target_domain} ---")

        # Run the heavy lifting in a separate thread to keep GUI responsive
        self.master.after(100, lambda: self._process_kaeferjaeger_data_async(target_domain))

    def _process_kaeferjaeger_data_async(self, target_domain):
        """Asynchronous function to download and process Kaeferjaeger data."""
        base_url = "https://kaeferjaeger.gay/?dir=sni-ip-ranges"
        try:
            # Fetch the directory listing page
            response = requests.get(base_url)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            html_content = response.text

            # Find all .txt file links using regex
            txt_files = re.findall(r'<a href="(.*?\.txt)">', html_content)
            if not txt_files:
                self.update_status("No .txt files found in the directory.")
                self.append_result("--- No results from Kaeferjaeger ---")
                return

            self.update_status(f"Downloading {len(txt_files)} files...")
            downloaded_files = []
            # Use ThreadPoolExecutor for concurrent downloads
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self._download_file, urljoin(base_url, f)) for f in txt_files]
                for future in futures:
                    try:
                        file_path = future.result()
                        if file_path:
                            downloaded_files.append(file_path)
                    except Exception as e:
                        self.append_result(f"Download error: {e}")

            if not downloaded_files:
                self.update_status("Failed to download any files.")
                self.append_result("--- No results from Kaeferjaeger ---")
                return

            self.update_status(f"Downloaded {len(downloaded_files)} files. Processing...")
            found_subdomains = set()
            # Process each downloaded file
            for file_path in downloaded_files:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            # Check if the target domain is present in the line
                            if f".{target_domain}" in line:
                                # Mimic the shell command's logic:
                                # awk -F'-- ' '{print $2}' | tr ' ' '\n' | tr '[' ' ' | sed 's/ //g' | sed 's/]//g'
                                parts = line.split('-- ')
                                if len(parts) > 1:
                                    subdomain_part = parts[1].strip()
                                    # Split by spaces, square brackets, and newlines
                                    cleaned_subdomains = re.split(r'[\s\[\]]+', subdomain_part)
                                    for sub in cleaned_subdomains:
                                        sub = sub.strip()
                                        # Ensure the extracted string is not empty and contains the target domain
                                        if sub and f".{target_domain}" in sub:
                                            found_subdomains.add(sub)
                except Exception as e:
                    self.append_result(f"Error reading file {os.path.basename(file_path)}: {e}")

            sorted_subdomains = sorted(list(found_subdomains))
            if sorted_subdomains:
                self.append_result(f"\n[+] Subdomains found from Kaeferjaeger for {target_domain}:")
                for sd in sorted_subdomains:
                    self.append_result(sd)
            else:
                self.append_result(f"\nNo subdomains found for {target_domain} in Kaeferjaeger data.")

            self.update_status("Kaeferjaeger data processing complete.")
            self.append_result("--- Kaeferjaeger data search finished ---")

        except requests.exceptions.RequestException as e:
            messagebox.showerror("Network Error", f"Error connecting to Kaeferjaeger: {e}")
            self.update_status("Failed to process Kaeferjaeger data.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            self.update_status("Failed to process Kaeferjaeger data.")
        finally:
            self._cleanup_temp_files() # Clean up downloaded files

    def _download_file(self, url):
        """Downloads a single file from the given URL to the temporary directory."""
        local_filename = os.path.join(self.temp_dir, url.split('/')[-1])
        try:
            with requests.get(url, stream=True) as r:
                r.raise_for_status() # Raise an exception for bad status codes
                with open(local_filename, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            return local_filename
        except requests.exceptions.RequestException as e:
            # Print to console for debugging, but don't show a messagebox for each failed download
            print(f"Failed to download {url}: {e}")
            return None

    def _cleanup_temp_files(self):
        """Removes all files from the temporary directory."""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir) # Remove directory and its contents
            os.makedirs(self.temp_dir, exist_ok=True) # Recreate empty directory for next run
        except Exception as e:
            print(f"Error cleaning up temporary files: {e}")

    def fetch_shodan_subdomains(self):
        """Initiates fetching subdomains using Shodan DNS API."""
        target_domain = self.domain_entry.get().strip()
        shodan_api_key = self.shodan_entry.get().strip()

        if not target_domain:
            messagebox.showwarning("Missing Input", "Please enter the target domain.")
            return
        if not shodan_api_key:
            messagebox.showwarning("Missing Input", "Please enter the Shodan API Key.")
            return

        self.update_status("Starting Shodan subdomain fetching...")
        self.append_result(f"--- Starting Shodan search for: {target_domain} ---")

        # Run the heavy lifting in a separate thread to keep GUI responsive
        self.master.after(100, lambda: self._fetch_shodan_subdomains_async(target_domain, shodan_api_key))

    def _fetch_shodan_subdomains_async(self, target_domain, shodan_api_key):
        """Asynchronous function to fetch subdomains from Shodan."""
        shodan_url = f"https://api.shodan.io/dns/domain/{target_domain}?key={shodan_api_key}"
        try:
            response = requests.get(shodan_url)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            data = response.json()

            if 'subdomains' in data and data['subdomains']:
                subdomains = set()
                for sub in data['subdomains']:
                    full_subdomain = f"{sub}.{target_domain}"
                    subdomains.add(full_subdomain)

                sorted_subdomains = sorted(list(subdomains)) # Simple alphabetical sort

                self.append_result(f"\n[+] Subdomains found from Shodan for {target_domain}:")
                for sd in sorted_subdomains:
                    self.append_result(sd)
            else:
                # Handle cases where 'subdomains' key is missing or empty
                error_message = data.get('error', 'No subdomains available.')
                self.append_result(f"\nNo subdomains found for {target_domain} via Shodan or the key is invalid. Reason: {error_message}")

            self.update_status("Shodan subdomain fetching complete.")
            self.append_result("--- Shodan search finished ---")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                messagebox.showerror("API Error", "Invalid Shodan API key. Please check it.")
            else:
                messagebox.showerror("Network Error", f"Error connecting to Shodan: {e}")
            self.update_status("Failed to fetch Shodan subdomains.")
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Network Error", f"Error connecting to Shodan: {e}")
            self.update_status("Failed to fetch Shodan subdomains.")
        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            self.update_status("Failed to fetch Shodan subdomains.")


def main():
    root = tk.Tk()
    app = SubdomainTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
