# Email-Threat-Interceptor# Email Threat Interceptor


An advanced, client-side intelligence dashboard for Gmail that provides a final, critical layer of defense against sophisticated phishing and social engineering attacks that bypass traditional server-side filters.

## Overview

In an era where cyber threats are increasingly sophisticated, relying solely on server-side email filters is no longer sufficient. The **Email Threat Interceptor** is a Manifest V3 Chrome Extension that injects a real-time security dashboard directly into the Gmail UI. It acts as a proactive "Heads-Up Display" for the user, providing actionable intelligence at the most critical moment—right before they click a link or trust a sender.

## Core Features

-   **✅ SPF & DMARC Validation:** Verifies that an email was sent from a server authorized by the domain owner.
-   **📅 Domain Age Analysis:** Checks the domain's creation date to flag newly created domains, a common tactic for phishing.
-   **🔗 Malicious URL Scanning:** Cross-references every link in the email against VirusTotal's massive database of known threats.
-   **🤫 Hidden Content Detection:** Performs a local scan to find and flag deceptive links, invisible tracking pixels, and other hidden elements.

## Getting Started

To run this project locally, follow these steps:

### Prerequisites

You will need to get free API keys from the following services:
-   [MXToolbox](https://mxtoolbox.com/web/signup) (Sign up for a free account to get an API key)
-   [IP2WHOIS](https://www.ip2whois.com/pricing) (Free plan available)
-   [VirusTotal](https://www.virustotal.com/) (Sign up to get your public API key)

### Installation

1.  **Clone the repository:**
    ```sh
    git clone [https://github.com/your-username/Email-Threat-Interceptor.git](https://github.com/your-username/Email-Threat-Interceptor.git)
    ```
2.  **Create your `config.js` file:**
    * In the project folder, make a copy of `config.example.js` and rename it to `config.js`.
    * Open `config.js` and add your real API keys from the services above.
3.  **Load the extension in Chrome:**
    * Open Chrome and navigate to `chrome://extensions`.
    * Enable **"Developer mode"** in the top-right corner.
    * Click **"Load unpacked"**.
    * Select your `Email-Threat-Interceptor` project folder.

The extension icon should now appear in your browser toolbar!

## Technology Stack

-   **Platform:** Chrome Extension (Manifest V3)
-   **Core:** JavaScript (ES6+), HTML5, CSS3
-   **APIs:** MXToolbox, IP2WHOIS, VirusTotal
