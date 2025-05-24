import os
import requests
import tarfile
import tempfile
import shutil

# Configuration
BLACKLIST_URL = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
CATEGORIES_FILE = "categories.txt"  # File containing categories, one per line
USER_ACTIONS_FILE = "/etc/privoxy/user.action"  # Adjust path as needed
#USER_ACTIONS_FILE = "./privoxy.test.user.action"  # Adjust path as needed
TMP_DIR = "/tmp/privoxy_blacklist"


def download_blacklist(url, dest):
  response = requests.get(url, stream=True)
  response.raise_for_status()
  with open(dest, "wb") as f:
    for chunk in response.iter_content(chunk_size=8192):
      f.write(chunk)

def extract_blacklist(tar_path, extract_to):
  with tarfile.open(tar_path, "r:gz") as tar:
    tar.extractall(path=extract_to)

def read_categories(file_path):
  with open(file_path, "r") as f:
    return [line.strip() for line in f if line.strip()]

def update_user_actions_streaming(categories, blacklist_dir, user_actions_path):
    start_marker = "# BEGIN PRIVOCYCT BLOCK"
    end_marker = "# END PRIVOCYCT BLOCK"

    temp_fd, temp_path = tempfile.mkstemp()
    block_written = False
    try:
        # Write to temp file
        with open(user_actions_path, "r") as src, os.fdopen(temp_fd, "w") as dst:
            in_block = False
            for line in src:
                if line.strip() == start_marker:
                    in_block = True
                    if not block_written:
                        # Write the new block
                        dst.write(start_marker + "\n")
                        dst.write("{ +block }\n")
                        # Stream domains directly
                        for cat in categories:
                            cat_file = os.path.join(blacklist_dir, "blacklists", cat, "domains")
                            if os.path.isfile(cat_file):
                                with open(cat_file, "r") as f:
                                    for domain_line in f:
                                        domain_line = domain_line.strip()
                                        if domain_line and not domain_line.startswith("#"):
                                            dst.write(f".{domain_line}\n")
                        dst.write(end_marker + "\n")
                        block_written = True
                    continue
                if line.strip() == end_marker:
                    in_block = False
                    continue
                if not in_block:
                    dst.write(line)
            if not block_written:
                # No block found, append at end
                dst.write("\n" + start_marker + "\n")
                dst.write("{ +block }\n")
                for cat in categories:
                    cat_file = os.path.join(blacklist_dir, "blacklists", cat, "domains")
                    if os.path.isfile(cat_file):
                        with open(cat_file, "r") as f:
                            for domain_line in f:
                                domain_line = domain_line.strip()
                                if domain_line and not domain_line.startswith("#"):
                                    dst.write(f".{domain_line}\n")
                dst.write(end_marker + "\n")
        shutil.move(temp_path, user_actions_path)
    except FileNotFoundError:
        with open(user_actions_path, "w") as f:
            f.write(start_marker + "\n")
            f.write("{ +block }\n")
            for cat in categories:
                cat_file = os.path.join(blacklist_dir, "blacklists", cat, "domains")
                if os.path.isfile(cat_file):
                    with open(cat_file, "r") as dfile:
                        for domain_line in dfile:
                            domain_line = domain_line.strip()
                            if domain_line and not domain_line.startswith("#"):
                                f.write(f".{domain_line}\n")
            f.write(end_marker + "\n")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
            
def chownPrivxoyUserActions(user_actions_path):
    try:
        import pwd
        import grp
        # Change ownership to 'privoxy' user and 'root' group
        privoxy_user = pwd.getpwnam("privoxy")
        group = grp.getgrnam("root")
        os.chown(user_actions_path, privoxy_user.pw_uid, group.gr_gid)
    except (KeyError, ImportError):
        print("Warning: Could not change ownership to 'privoxy'. Ensure the script is run with appropriate permissions.")

def main():
  os.makedirs(TMP_DIR, exist_ok=True)
  tar_path = os.path.join(TMP_DIR, "blacklists.tar.gz")
  print("Downloading blacklist...")
  download_blacklist(BLACKLIST_URL, tar_path)
  print("Extracting blacklist...")
  extract_blacklist(tar_path, TMP_DIR)
  categories = read_categories(CATEGORIES_FILE)
  print(f"Using categories: {categories}")
  print("Updating user actions...")
  update_user_actions_streaming(categories, TMP_DIR, USER_ACTIONS_FILE)
  chownPrivxoyUserActions(USER_ACTIONS_FILE)
  print(f"Updated {USER_ACTIONS_FILE} with blocked domains.")

if __name__ == "__main__":
  main()