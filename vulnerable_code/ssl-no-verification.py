# To establish a SSL/TLS connection not vulnerable to 
# man-in-the-middle attacks, it’s essential to make sure 
# the server presents the right certificate.
#
# Source: https://github.com/dehvCurtis/vulnerable-code-examples/blob/main/SAST/python/verification/ssl-standard.py

import ssl

ctx = ssl._create_unverified_context() # Noncompliant: by default hostname verification is not done
ctx = ssl._create_stdlib_context() # Noncompliant: by default hostname verification is not done

ctx = ssl.create_default_context()
ctx.check_hostname = False # Noncompliant

ctx = ssl._create_default_https_context()
ctx.check_hostname = False # Noncompliant