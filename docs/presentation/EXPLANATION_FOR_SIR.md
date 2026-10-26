Good evening Sir,

To clearly explain what our system actually does at each layer, here is the simple step-by-step breakdown of how the whole pipeline works from start to finish:

---

#### Step 1: Making and Planting the Traps (Layer 1)
* **What we do:** We create realistic fake files and credentials (honeytokens) and plant them where an insider might snoop around.
* **How it works:**
  * **Word Files (.docx):** We make a normal-looking confidential document (like *Executive_Salaries.docx*) and hide a tiny tracking link inside it. When someone opens the document in Microsoft Word, Word quietly pings our server in the background to load an invisible 1-pixel image.
  * **PDF Files (.pdf):** When opened in a PDF viewer, the file automatically triggers a silent background link back to our server.
  * **API Keys:** We generate fake cloud keys (like AWS or Stripe keys) and leave them inside `.env` configuration files or git repositories.
* **Why it matters:** It gives us an active trap. The moment someone touches something they shouldn't, we know.

---

#### Step 2: Catching the Access Silently (Layer 2)
* **What we do:** When the insider opens the file or tests the fake API key, our server catches them without tipping them off.
* **How it works:**
  * **Getting the real IP:** Even if the person is behind a company proxy or load balancer, we read the real workstation IP from the request headers (`X-Forwarded-For`). We also record their browser/tool type and the exact time.
  * **Keeping it silent:**
    * If they opened a document, our server sends back a blank 1-pixel image. They see their document open normally with zero error messages.
    * If they tested an API key on our verification route, our server returns a standard `401 Unauthorized (Invalid or expired token)`. The attacker simply thinks the key is old and expired, not that they were caught.
  * **Spam protection:** If someone runs an automated tool that hits the link hundreds of times per second, our rate limiter stops writing to the database so our server does not crash.

---

#### Step 3: Checking and Cleaning the Data (Layer 3)
* **What we do:** Before we do anything with the incoming data, we clean it up and make sure it is safe.
* **How it works:** We use Pydantic models to verify the data. It checks that the IP address is valid, removes any unwanted spaces or port numbers, and makes sure all numbers are within safe limits.
* **Why it matters:** It prevents messy logs, bad database entries, or errors caused by strange characters.

---

#### Step 4: Saving the Event in the Database (Layer 4)
* **What we do:** We check if the trap is still active and record the event.
* **How it works:**
  * The system looks up the token ID in our database.
  * If the token was already turned off (revoked) by an admin, the system stops here and does not raise an alert. This stops old, decommissioned files from spamming the team.
  * If the token is active, it saves a new record with the person's IP, their tool/browser name, all request headers, and the exact timestamp.

---

#### Step 5: Calculating the Risk Score (Layer 5)
* **What we do:** Most tools just trigger a simple yes/no alarm. Instead, we calculate a risk score so the security team knows which alerts are emergencies and which are minor.
* **The formula:**
  $$\text{Final Risk Score} = \text{Asset Weight} \times \text{Context Multiplier} \times \text{Frequency Multiplier}$$
* **How it works:**
  1. **Asset Weight (1 to 50):** How important was the file? A general wiki guide might be set to 15, while a master payroll file is set to 40 or 50.
  2. **Context Multiplier (Time & Tool):**
     * If opened during normal office hours (Monday–Friday, 8 AM to 7 PM), the multiplier is **1.0x**.
     * If opened late at night or over the weekend, the multiplier jumps to **1.5x** because after-hours access is much more suspicious.
     * If opened using an automated hacking tool or command-line script (`curl`, `python-requests`, `nmap`), an extra **1.2x** multiplier is added.
  3. **Frequency Multiplier (5-minute window):**
     * 1 single click = **1.0x** (could just be an accidental click).
     * 2 to 4 clicks = **1.3x** (someone is browsing around).
     * 5 or more clicks = **1.8x** (an automated script is running or trying a brute-force attack).
  4. **Severity Label:** Based on the final score, the alert is labeled **Low** (0–25), **Medium** (26–50), **High** (51–75), or **Critical** (above 75).

---

#### Step 6: Sending the Alert in Real Time (Layer 6)
* **What we do:** As soon as the score is calculated, we send the alert to the dashboard immediately.
* **How it works:** We use Server-Sent Events (SSE). Instead of the dashboard having to refresh or poll the server every few seconds, the server keeps an open connection and pushes the alert to the browser in under 1 millisecond.

---

#### Step 7: Showing the Alert on the Admin Dashboard (Layer 7)
* **What we do:** The security admin sees the incident on their screen right away.
* **How it works:**
  * The dashboard counter updates and a colored badge appears (Blue for Low, Yellow for Medium, Orange for High, Red for Critical).
  * The admin can click on the alert to see the full story: the person's IP, the tool they used, what time they opened it, and exactly how the score was calculated.
  * If needed, the admin can click a single **"Revoke"** button to deactivate that trap immediately.

---

#### Step 8: Testing and Verification (Layer 8)
* **What we do:** We prove that this whole pipeline works fast and reliably.
* **How it works:** We wrote an automated test script (`simulate_attacks.py`) that runs 4 different attack types (a single click, an after-hours click, a fast script burst, and a test on a revoked key). Every single alert arrived at the dashboard in **less than 15 milliseconds**, with zero missed detections across our 47 automated tests.

---

### A Real-World Example:

1. **The Trap:** An admin places a Word file named `Executive_Salaries.docx` (Asset Weight = 40) in a shared company folder.
2. **The Incident:** An employee opens this file on Friday at 9:45 PM (outside office hours) from their laptop (IP: `10.0.4.12`).
3. **The Catch:** Word quietly loads our invisible tracking pixel. Our server logs the IP and time, and sends back the blank image. The employee sees the Word file open normally with zero suspicion.
4. **The Score:**
   * Asset Weight = 40
   * Context = 1.5x (because it happened at 9:45 PM, outside 8 AM–7 PM business hours)
   * Frequency = 1.0x (first time opening it)
   * **Score = 40 × 1.5 × 1.0 = 60.00** $\to$ **HIGH SEVERITY**
5. **The Reaction:** In under 6 milliseconds, an Orange "High Severity" alert appears on the admin dashboard showing the employee's laptop IP (`10.0.4.12`), allowing the security team to check on it immediately.
