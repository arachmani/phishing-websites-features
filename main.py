import ssl, socket
from urllib.parse import urlparse
import time
from datetime import datetime
import netaddr
import whois
import favicon
import socket

hostname = 'https://www.google.com/'

legitimate = 1
suspcious = 0
phishing = -1

# 4.1.1 having_IP_Address:
def having_ip_address(url):
    print("###  having_ip_address: " + url + "  ####")
    parsed_url = urlparse(url)
    try:
        netaddr.IPAddress(parsed_url.netloc)
        return phishing
    except:
        return legitimate

# 4.1.2 URL_Length
def url_length(url):
    print("###  URL_Length: " + url + "  ####")
    if len(url) >= 54:
        return phishing
    else:
        return legitimate

# 4.1.3 Shortining_Service
def shortining_Service(url):
    print("###  shortining_Service: " + url + "  ####")
    parsed_url = urlparse(url)
    if parsed_url.netloc == "tinyurl.com":
        return phishing
    else:
        return legitimate

# 4.1.4 having_At_Symbol
def having_At_Symbol(url):
    print("###  having_At_Symbol: " + url + "  ####")
    if "@" in url:
        return phishing
    else:
        return legitimate

# 4.1.5 double_slash_redirecting
def double_slash_redirecting(url):
    print("###  double_slash_redirecting: " + url + "  ####")
    if "//" in url[7:]:
        return phishing
    else:
        return legitimate

# 4.1.6 Prefix_Suffix
def prefix_suffix(url):
    print("###  prefix_suffix " + url + "  ####")
    parsed_url = urlparse(url)
    if "-" in parsed_url.netloc:
        return phishing
    else:
        return legitimate

# 4.1.7 having_Sub_Domain
def having_Sub_Domain(url):
    print("###  having_Sub_Domain " + url + "  ####")
    parsed_url = urlparse(url)
    dot_number = parsed_url.netloc.count(".") - 1 # the first dot in the after the “www” is omitted
    if dot_number == 1:
        return legitimate
    elif dot_number > 2:
        return phishing
    else:
        return suspcious

# 4.1.8 SSLfinal_State
def SSLfinal_State(url):
    print("###  SSLfinal_State: " + url + "  ####")
    parsed_url = urlparse(url)
    if parsed_url.scheme == "https":
        print("- url start with https")

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=parsed_url.netloc) as s:
            s.connect((parsed_url.netloc, 443))
            cert = s.getpeercert()
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject['commonName']
        issuer = dict(x[0] for x in cert['issuer'])
        issuerOrganizationName = issuer["organizationName"]
        issued_by = issuer['commonName']

        trustedOrgList = ['GeoTrust', 'DigiCert Inc', 'GoDaddy', 'Network Solutions', 'Thawte', 'Comodo', 'Doster', 'VeriSign']
        if issuerOrganizationName in trustedOrgList:
            print("- Issued is in trusted list - " + issuerOrganizationName)

            # Calculate time
            seconds_since_epoch = time.time()
            # current_time = time.ctime(seconds_since_epoch)
            cert_exp_date = time.strptime(cert['notAfter'][:-4], '%b %d %H:%M:%S %Y') #conver to time format
            delta_in_sec = time.mktime(cert_exp_date) - seconds_since_epoch
            delta_in_years = delta_in_sec/60/60/24/365.25

            if delta_in_years >= 1.0:
                print("- Cert exp date is >= 1 year")
                return legitimate
            else:
                print("- Cert exp date is < 1 year")
                return suspcious
        else:
            print("- Issued is not in trusted list - " + issuerOrganizationName)
            return suspcious
    else:
        print("- url doesn't start with https")
        return phishing

# 4.1.9 Domain_registeration_length
def domain_registeration_length(url):
    print("###  domain_registeration_length: " + url + "  ####")
    now = datetime.now()
    w = whois.whois(url)
    if type(w.expiration_date) == list:
        domain_exp_date = w.expiration_date[0]
    else:
        domain_exp_date = w.expiration_date
    time_delta = domain_exp_date - now
    if time_delta.days > 365:
        return legitimate
    else:
        return phishing

# 4.1.10 Favicon
def check_favicon(url):
    print("###  check_favicon: " + url + "  ####")
    icons = favicon.get(url)
    parsed_url = urlparse(url)
    for icon in icons:
        parsed_icon = urlparse(icon.url)
        # print(parsed_icon.netloc)
        # print(parsed_url.netloc)
        if parsed_icon.netloc != parsed_url.netloc:
            return phishing
    return legitimate

# 4.1.11 port
def open_ports(url):
    print("###  open_ports: " + url + "  ####")
    parsed_url = urlparse(url)
    port_list = [21, 22, 23, 445, 1433, 1521, 3306, 3389]
    host = socket.gethostbyname(parsed_url.netloc)
    print(host)
    for port in port_list:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)
            result = s.connect_ex((host, port))
            if result == 0:
                print(f'Port is opened - {host}:{port}')
                return phishing
            print(f'Port is close - {host}:{port}')
    return legitimate

# 4.1.12 HTTPS_token
def https_token(url):
    print("###  https_token: " + url + "  ####")
    parsed_url = urlparse(url)
    if "https" in parsed_url.netloc:
        return phishing
    return legitimate

# Test
# print(having_Sub_Domain("https://www.google.co.il.ru"))
# print(prefix_suffix("http://www.legi-timate.com"))
# print(double_slash_redirecting("http://www.legitimate.com//http://www.phishing.com"))
# print(having_At_Symbol("https://tinyurl.com/4sbr2usn"))
# print(shortining_Service("https://tinyurl.com/4sbr2usn"))
# print(url_length(hostname))
# print(having_ip_address(hostname))
# print(SSLfinal_State("https://www.GeoTrust.com"))
# print(domain_registeration_length("https://www.google.com"))
# print(check_favicon('https://www.github.com'))
# print(check_favicon('https://www.python.org'))
# print(open_ports("https://www.walla.com"))
print(https_token("http://https-www-paypal-it-webapps-home.soft-hair.com/"))
