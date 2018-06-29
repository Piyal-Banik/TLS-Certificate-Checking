# TLS-Certificate-Checking
Following things are checked:
1. validation of dates, both the Not Before and Not After dates
2. domain name validation (including Subject Alternative Name (SAN)
extension) and wildcards
3. minimum key length of 2048 bits for RSA
4. correct key usage, including extensions
A C program that reads in a CSV (comma separated
value) file that contains two columns. The first column provides the file
path for the certificate to test. The second column provides the URL from
which that certificate belongs. The program steps through each line
in the CSV file, loads the certificate specified in column one, and validates it,
including checking the URL contained in column two.
