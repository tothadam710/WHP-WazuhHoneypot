import os
import shutil
import datetime


def create_archives():
    #archive outputs(cowrie_linux_output, windows_output) from root folder to archives/archived_artifacts with timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.make_archive(f"archives/archived_artifacts/archived_artifacts_{timestamp}_cowrie", 'zip', "cowrie_linux_output")
    shutil.make_archive(f"archives/archived_artifacts/archived_artifacts_{timestamp}_windows", 'zip', "windows_output")
    
    #create artifacts
    shutil.make_archive("artifacts/cowrie_linux_output", 'zip', "cowrie_linux_output")
    shutil.make_archive("artifacts/windows_output", 'zip', "windows_output")

    #archive resources folder contents to archives/archived_resources with timestamp
    shutil.make_archive(f"archives/archived_resources/archived_resources_{timestamp}", 'zip', "resources")
    cleanup()

  
def cleanup():
    #empty resources folder
    for root, dirs, files in os.walk("resources"):
        for file in files:
            os.remove(os.path.join(root, file))
        for dir in dirs:
            shutil.rmtree(os.path.join(root, dir))
    #delete cowrie_linux_output and windows_output folders from root folder
    if os.path.exists("cowrie_linux_output"):
        shutil.rmtree("cowrie_linux_output")
    if os.path.exists("windows_output"):
        shutil.rmtree("windows_output")