import ssl, socket
from urllib.parse import urlparse
import time
import netaddr

hostname = 'https://www.google.com/'

# 1 = Legitimate
# 0 = suspcious
# -1 = Phishing

# 4.1.1 having_IP_Address:
def having_ip_address(url):
    print("###  having_ip_address: " + url + "  ####")
    parsed_url = urlparse(url)
    try:
        netaddr.IPAddress(parsed_url.netloc)
        return -1
    except:
        return 1

# 4.1.8 SSLfinal_State
def is_ssl_trusted(url):

    print("###  is_ssl_trusted: " + url + "  ####")
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
                return 1    # legitimate
            else:
                print("- Cert exp date is < 1 year")
                return 0
        else:
            print("- Issued is not in trusted list - " + issuerOrganizationName)
            return 0    # Suspicious
    else:
        print("- url doesn't start with https")
        return -1

# Test
print(having_ip_address(hostname))
print(is_ssl_trusted(hostname))
