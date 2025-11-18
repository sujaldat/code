I'll help you work through this PKI (Public Key Infrastructure) lab step by step. This is a comprehensive security lab about certificate authorities, HTTPS, and man-in-the-middle attacks.

Let me break down each task and provide guidance:

## **Task 1: Become a Certificate Authority (CA)**

### Step 1: Set up the OpenSSL configuration

```bash
# Copy the OpenSSL configuration file
cp /usr/lib/ssl/openssl.cnf .

# Create the required directory structure
mkdir demoCA
mkdir demoCA/certs
mkdir demoCA/crl
mkdir demoCA/newcerts
touch demoCA/index.txt
echo 1000 > demoCA/serial
```

### Step 2: Generate the CA certificate

```bash
openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf
```

When prompted:
- Enter a password (remember it!)
- Fill in Country Name, State, Organization, Common Name, etc.

### Step 3: Examine the certificate

```bash
# View the certificate
openssl x509 -in ca.crt -text -noout

# View the private key
openssl rsa -in ca.key -text -noout
```

**What to look for:**
1. **CA indicator**: Look for `CA:TRUE` in the Basic Constraints section
2. **Self-signed indicator**: The Issuer and Subject fields will be identical

**Deliverables for Task 1:**
- Screenshot showing `CA:TRUE` (highlighted)
- Screenshot showing Issuer = Subject (highlighted)
- Explain what a CA is
- Explain why CAs are important for the CIA triad (Confidentiality, Integrity, Availability)

---

## **Task 2: Create Certificate Signing Request for Your Server**

**Important**: Replace `www.bank32.com` with your server name format: `www.[ubitname][year].com`

Example: If your UBIT is `josmit2` and the year is 2025, use `www.josmit22025.com`

### Step 1: Update /etc/hosts

```bash
sudo nano /etc/hosts
```

Add:
```
10.9.0.80 www.bank32.com
10.9.0.80 www.[your-ubit-name][year].com
```

### Step 2: Generate CSR with SANs

```bash
openssl req -newkey rsa:2048 -sha256 \
    -keyout server.key -out server.csr \
    -subj "/CN=www.[yourubit][year].com/O=Your Org/C=US" \
    -passout pass:dees \
    -addext "subjectAltName = DNS:www.[yourubit][year].com, \
                              DNS:www.[yourubit][year]A.com, \
                              DNS:www.[yourubit][year]B.com"
```

### Step 3: Verify the CSR

```bash
openssl req -in server.csr -text -noout
openssl rsa -in server.key -text -noout
```

**Deliverables for Task 2:**
- Screenshot of CSR showing the Subject Alternative Names
- Screenshot of the key file
- Explain what else SANs can secure (answer: IP addresses, email addresses, URIs)

---

## **Task 3: Generate Certificate for Your Server**

### Step 1: Modify the configuration file

```bash
nano openssl.cnf
```

Find and uncomment:
```
copy_extensions = copy
```

### Step 2: Sign the certificate

```bash
openssl ca -config openssl.cnf -policy policy_anything \
    -md sha256 -days 3650 \
    -in server.csr -out server.crt -batch \
    -cert ca.crt -keyfile ca.key
```

### Step 3: Verify the certificate

```bash
openssl x509 -in server.crt -text -noout
```

**Deliverables for Task 3:**
- Screenshot of server.crt showing SANs
- Explain why the default policy couldn't be used (answer: it requires subject fields to match the CA's certificate)

---

## **Task 4: Deploy HTTPS Website**

### Step 1: Create Apache configuration

Create a file in the volumes folder (shared with container):

```bash
nano volumes/[yourubit][year]_apache_ssl.conf
```

Add:
```apache
<VirtualHost *:443>
    DocumentRoot /var/www/[yourubit][year]
    ServerName www.[yourubit][year].com
    ServerAlias www.[yourubit][year]A.com
    ServerAlias www.[yourubit][year]B.com
    DirectoryIndex index.html
    
    SSLEngine On
    SSLCertificateFile /certs/server.crt
    SSLCertificateKeyFile /certs/server.key
</VirtualHost>
```

### Step 2: Copy certificates to volumes folder

```bash
cp server.crt volumes/
cp server.key volumes/
cp ca.crt volumes/
```

### Step 3: Enter the container and set up

```bash
docker exec -it [container-name] /bin/bash

# Inside container:
mkdir -p /var/www/[yourubit][year]
echo "<h1>Welcome to [yourubit][year]</h1>" > /var/www/[yourubit][year]/index.html

cp /volumes/server.crt /certs/
cp /volumes/server.key /certs/
cp /volumes/[yourubit][year]_apache_ssl.conf /etc/apache2/sites-available/

a2ensite [yourubit][year]_apache_ssl
service apache2 start
```

Enter password: `dees`

### Step 4: Browse to https://www.[yourubit][year].com

**Before importing CA:**
- You'll see a security warning
- Browser doesn't trust the certificate
- Reason: Your CA is not in the browser's trusted store

### Step 5: Import CA certificate to Firefox

1. Go to `about:preferences#privacy`
2. Scroll to "Certificates" → "View Certificates"
3. Click "Authorities" tab
4. Click "Import" → select `ca.crt`
5. Check "Trust this CA to identify websites"

**After importing:**
- Site loads without warnings
- Green padlock appears

**Deliverables for Task 4:**
- List of steps and commands
- Screenshot of Apache config
- Screenshot of browser warning (before)
- Screenshot of successful HTTPS (after)
- Explain the difference

---

## **Task 5: MITM Attack (PKI Defense)**

### Step 1: Set up malicious site

Add to Apache config:
```apache
<VirtualHost *:443>
    DocumentRoot /var/www/fake
    ServerName www.example.com
    
    SSLEngine On
    SSLCertificateFile /certs/server.crt
    SSLCertificateKeyFile /certs/server.key
</VirtualHost>
```

Create fake site:
```bash
mkdir /var/www/fake
echo "<h1>Fake Example.com - Enter Password</h1>" > /var/www/fake/index.html
```

### Step 2: Modify /etc/hosts

```bash
sudo nano /etc/hosts
```

Add:
```
10.9.0.80 www.example.com
```

### Step 3: Browse to https://www.example.com

**Result**: Browser will show a security warning!

**Deliverables for Task 5:**
- Screenshot of security warning
- Explain: Certificate's CN doesn't match www.example.com
- Explain: Attacker can't create valid cert for example.com without the real CA's private key

---

## **Task 6: MITM with Compromised CA**

### Step 1: Create certificate for example.com

```bash
openssl req -newkey rsa:2048 -sha256 \
    -keyout example.key -out example.csr \
    -subj "/CN=www.example.com/O=Example Inc./C=US" \
    -passout pass:dees

openssl ca -config openssl.cnf -policy policy_anything \
    -md sha256 -days 3650 \
    -in example.csr -out example.crt -batch \
    -cert ca.crt -keyfile ca.key
```

### Step 2: Update Apache to use new certificate

```apache
<VirtualHost *:443>
    DocumentRoot /var/www/fake
    ServerName www.example.com
    
    SSLEngine On
    SSLCertificateFile /certs/example.crt
    SSLCertificateKeyFile /certs/example.key
</VirtualHost>
```

### Step 3: Browse to https://www.example.com

**Result**: No warning! The attack succeeds because the browser trusts your compromised CA.

**Deliverables for Task 6:**
- Screenshot showing successful MITM (no warnings)

---

## **Key Concepts Summary**

1. **CA**: Trusted entity that signs certificates
2. **Self-signed**: Issuer = Subject
3. **SAN**: Allows multiple names on one certificate
4. **PKI Defense**: Browser checks if certificate matches hostname and is signed by trusted CA
5. **Compromised CA**: Can issue valid certificates for any domain

Would you like me to create detailed artifacts for any specific task, such as configuration files or scripts to automate parts of this lab?
