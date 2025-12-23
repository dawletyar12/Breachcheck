 Password Strength & Breach Checker
 Description

A simple web service that:

Evaluates password strength using the zxcvbn
 library.

Checks whether a password has been found in data breaches via the Have I Been Pwned Pwned Passwords API
.

⚠ Security:

Passwords are not stored and never fully transmitted to the server.

The k-anonymity method is used: only the first 5 characters of the password’s SHA-1 hash are sent.

This ensures privacy of the check.

 Run locally
git clone https://github.com/dawletyar12/dawletyar.git
cd dawletyar
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
