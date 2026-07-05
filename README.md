# LogIQ

LogIQ is a desktop log analysis tool designed to simplify security log investigation by automatically detecting supported log formats and presenting useful information through a modern graphical interface. Instead of manually searching through thousands of log entries, LogIQ summarizes authentication activity, highlights suspicious IP addresses, identifies failed and successful logins, calculates a threat score, and generates an easy-to-read report.

LogIQ is built with Python and CustomTkinter and is designed to be modular, allowing support for additional log formats and analysis features to be added over time. The long-term goal is to provide a lightweight, fast, and easy-to-use alternative for quickly reviewing logs without the complexity of a full SIEM.

Current support includes Linux SSH authentication logs, with Windows Event Logs, Apache, Nginx, firewall logs, IOC detection, and additional reporting features planned for future releases.
