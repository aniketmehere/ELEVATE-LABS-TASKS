Setup and Use a Firewall on Linux (UFW)

Objective
To configure and test basic firewall rules to allow or block traffic using UFW on Linux, ensuring secure management of inbound and outbound connections.

What Was Done
1.	Opened the UFW firewall tool via the terminal.
2.	Checked the current firewall status and listed existing rules using sudo ufw status verbose and sudo ufw status numbered.
3.	Added a rule to block inbound traffic on port 23 (Telnet) using sudo ufw deny 23.
4.	Tested the block by attempting to connect to port 23 locally, which was refused.
5.	Added a rule to allow SSH (port 22) using sudo ufw allow 22.
6.	Removed the test block rule for port 23 using sudo ufw delete deny 23 to restore the original state.
7.	Documented all commands and verified rules at each step.

How a Firewall Filters Traffic
A firewall monitors and controls incoming and outgoing network traffic based on predefined rules:
•	Allows legitimate traffic (e.g., SSH for remote management).
•	Blocks unauthorized traffic (e.g., Telnet port blocked to prevent attacks).
•	Acts as a barrier between trusted and untrusted networks, ensuring only authorized connections pass through.


Outcome
•	Successfully blocked unwanted traffic on port 23 and allowed SSH on port 22.
•	Verified that firewall rules were working as intended through local connection tests.
•	Original firewall state restored after removing test rules.
•	Demonstrated understanding of firewall configuration and traffic filtering using UFW.


