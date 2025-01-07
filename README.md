# Apple ID Unlocker

This script automates the process of unlocking Apple ID accounts by solving captcha challenges, verifying account details, and resetting the password. The script uses the `requests` library for all HTTP requests, ensuring simplicity and flexibility. Captcha challenges are solved using the **YesCaptcha** service.

---

## Features

- Fully automated process for Apple ID unlocking.
- Captcha solving via the [YesCaptcha](https://yescaptcha.com) service.
- Security question verification and response.
- Password reset with a new password provided in the configuration.
- Multi-threaded support for processing multiple accounts.
- VPN integration for bypassing rate limits or IP bans.

---

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd <repository-folder>
