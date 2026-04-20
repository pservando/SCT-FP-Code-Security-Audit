# SCT Final Assignment
# Code Source: https://github.com/dehvCurtis/vulnerable-code-examples

from Crypto.Cipher import *
from flask import request, Flask, redirect
import logging
import os
import ssl
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Strong cipher algorithms are cryptographic systems resistant to 
# cryptanalysis, they are not vulnerable to well-known attacks like 
# brute force attacks for example.

# It’s not recommended to use algorithm with a block size inferior 
# than 128 bits.


des3 = DES.new('ChangeIt') # Noncompliant: DES works with 56-bit keys allow attacks via exhaustive search
tdes3 = DES3.new('ChangeItChangeIt') # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack
bf2 = Blowfish.new('ChangeItWithYourKey', Blowfish.MODE_CBC, 'ChangeIt') # Noncompliant: Blowfish use a 64-bit block size makes it
rc21 = ARC2.new('ChangeItWithYourKey', ARC2.MODE_CFB, 'ChangeIt') # Noncompliant: RC2 is vulnerable to a related-key attack
rc41 = ARC4.new('ChangeItWithYourKey') # Noncompliant: vulnerable to several attacks (see https://en.wikipedia.org/wiki/RC4#Security)


    # OWASP Top 10 2021 Category A2 - Cryptographic Failures
    # OWASP Top 10 2017 Category A6 - Security Misconfiguration
    # MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
    # SANS Top 25 - Porous Defenses

# The following code is vulnerable to arbitrary code execution because it runs dynamic Python code based on untrusted data.

@app.route("/")
def example():
    operation = request.args.get("operation")
    eval(f"product_{operation}()") # Noncompliant
    return "OK"

# The following code is vulnerable to log injection as it constructs
# log entries using untrusted data. An attacker can leverage this to
# manipulate the chain of events being recorded.

import logging

app = Flask(__name__)

@app.route('/example')
def log():
    data = request.args["data"]
    app.logger.critical("%s", data) # Noncompliant

# The following code is vulnerable to command injections because 
# it is using untrusted inputs to set up a new process. Therefore 
# an attacker can execute an arbitrary program that is installed 
# on the system.

def ping():
    cmd = "ping -c 1 %s" % request.args.get("host", "www.google.com")
    status = os.system(cmd) # Noncompliant
    return str(status == 0)

# (CWE-359)
# This sample Python file contains a function that prints a password to the console without any security measures.
# It can be used to test SAST tools' ability to identify sensitive information exposure.

def insecure_function(password):
    print("Received password: " + password)

user_input = "sensitivePassword"
insecure_function(user_input)

# The following noncompliant code example is vulnerable 
# to open redirection as it constructs a URL with 
# user-controllable data. This URL is then used to 
# redirect the user without being first validated. An 
# attacker can leverage this to manipulate users into 
# performing unwanted redirects.

app = Flask("example")

@app.route("/redirect")
def redirect():
    url = request.args["url"]
    return redirect(url) # Noncompliant

# To establish a SSL/TLS connection not vulnerable to 
# man-in-the-middle attacks, it’s essential to make sure 
# the server presents the right certificate.

ctx = ssl._create_unverified_context() # Noncompliant: by default hostname verification is not done
ctx = ssl._create_stdlib_context() # Noncompliant: by default hostname verification is not done

ctx = ssl.create_default_context()
ctx.check_hostname = False # Noncompliant

ctx = ssl._create_default_https_context()
ctx.check_hostname = False # Noncompliant

# Strong cipher algorithms are cryptographic systems resistant to 
# cryptanalysis, they are not vulnerable to well-known attacks like 
# brute force attacks for example.

# It’s not recommended to use algorithm with a block size inferior 
# than 128 bits.

key = os.urandom(16)
iv = os.urandom(16)

tdes4 = Cipher(algorithms.TripleDES(key), mode=None, backend=default_backend()) # Noncompliant: Triple DES is vulnerable to meet-in-the-middle attack
bf3 = Cipher(algorithms.Blowfish(key), mode=None, backend=default_backend()) # Noncompliant: Blowfish use a 64-bit block size makes it vulnerable to birthday attacks
rc42 = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend()) # Noncompliant: vulnerable to several attacks (see https://en.wikipedia.org/wiki/RC4#Security

    # OWASP Top 10 2021 Category A2 - Cryptographic Failures
    # OWASP Top 10 2017 Category A6 - Security Misconfiguration
    # MITRE, CWE-327 - Use of a Broken or Risky Cryptographic Algorithm
    # SANS Top 25 - Porous Defenses