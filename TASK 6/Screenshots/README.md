
**Objective:**  
The objective of this task was to understand what makes a password strong and test it using an online password strength tool.  
The goal was to learn best practices for password creation, identify weaknesses, and analyze how complexity affects password security.



**Tools Used:**  
**Password Strength Checker:** [PasswordMeter.com](https://passwordmeter.com)  
This tool evaluates password strength based on:  
- Length  
- Uppercase & lowercase letters  
- Numbers  
- Symbols  
- Placement of numbers/symbols  
- Repetition & sequential patterns  



**Results:**  
I tested multiple passwords with increasing complexity and recorded their scores from the PasswordMeter tool.

| **Password**         | **Score** | **Complexity**  | **Observations** |
|----------------------|------------|-----------------|------------------|
| `aniket`            | 8%         | Very Weak       | Short, only lowercase letters, lacks numbers and symbols. |
| `aniket@`           | 26%        | Weak            | Added symbol, slightly stronger but still lacks uppercase and digits. |
| `aniket@123`        | 63%        | Strong          | Added numbers and symbol, meets most requirements. |
| `Aniket@123`        | 87%        | Very Strong     | Added uppercase letter, significantly improved strength. |
| `Aniket@1234`       | 96%        | Very Strong     | Longer length and mixed characters further improve security. |
| `Aniket@1234@$S%`   | 100%       | Very Strong     | Excellent length, high randomness, contains all character types. |

*(Screenshots of all password tests are included in this repository for reference.)*



**Analysis:**  

**Factors Improving Password Strength**  
- Length: Longer passwords score higher and are harder to crack.  
- Character Variety: Use a combination of uppercase, lowercase, numbers, and symbols.  
- Randomness: Avoid predictable patterns or dictionary words.  
- Symbol/Number Placement: Distributing numbers and symbols in the middle enhances strength.  

**Factors Reducing Password Strength**  
- Only Letters or Numbers: Simple and easy to guess.  
- Sequential Characters: Patterns like `123`, `abc`, or `qwerty` weaken passwords.  
- Repetition: Repeated characters reduce entropy.  
- Common Words: Easily cracked via dictionary attacks.  


**Best Practices for Creating Strong Passwords**  
1) Use at least **12–14 characters**.  
2) Combine **uppercase, lowercase, digits, and symbols**.  
3) Avoid **dictionary words** or **personal information**.  
4) Avoid **sequences** (`abc123`) and **repetition**.  
5) Place **symbols/numbers in the middle** for extra strength.  
6) Use **passphrases** (e.g., `Purple!Tiger$Runs2025`).  
7) Consider using a **password manager** to store strong, unique passwords.  



**Common Password Attacks**

| **Attack Type** | **Description** | **How to Protect** |
|-----------------|------------------|--------------------|
| **Brute Force** | Tries every possible combination. | Use long, complex passwords. |
| **Dictionary Attack** | Uses common words or leaked passwords. | Avoid dictionary words or names. |
| **Credential Stuffing** | Reuses leaked credentials across multiple accounts. | Use unique passwords per site. |
| **Phishing** | Tricks users into revealing passwords. | Verify site URLs and enable 2FA. |



**Key Learnings:**  
- Even small improvements (like adding symbols or uppercase letters) can drastically improve strength.  
- Password **length** plays a critical role in resisting brute-force attacks.  
- **Complex and unpredictable** passwords are significantly more secure.  
- Tools like PasswordMeter visually demonstrate how password quality improves with complexity.  



**Outcome:**  
After testing multiple passwords, I observed that complexity, randomness, and length are the key elements of a strong password.  
My final password `Aniket@1234@$S%` achieved **100% score** with **Very Strong** complexity, making it highly resistant to brute-force and dictionary attacks.



**Screenshots Included:**  
1. `aniket` – 8% (Very Weak)  
2. `aniket@` – 26% (Weak)  
3. `aniket@123` – 63% (Strong)  
4. `Aniket@123` – 87% (Very Strong)  
5. `Aniket@1234` – 96% (Very Strong)  
6. `Aniket@1234@$S%` – 100% (Very Strong)
