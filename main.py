import socket
import ssl
import time
from datetime import datetime
from urllib.parse import urlparse

import favicon
import netaddr
import requests
import whois
from bs4 import BeautifulSoup

hostname = "https://www.google.com/"

legitimate = 1
suspicious = 0
phishing = -1

# 1
# 4.1.1 having_IP_Address:
def having_ip_address(url):
    print("###  having_ip_address: " + url + "  ####")
    parsed_url = urlparse(url)
    try:
        netaddr.IPAddress(parsed_url.netloc)
        return phishing
    except:
        return legitimate


# 2
# 4.1.2 URL_Length
def url_length(url):
    print("###  URL_Length: " + url + "  ####")
    if len(url) < 54:
        return legitimate
    elif len(url) > 75:
        return phishing
    else:
        suspicious


# 3
# 4.1.3 Shortining_Service
def shortining_Service(url):
    print("###  shortining_Service: " + url + "  ####")
    parsed_url = urlparse(url)
    if parsed_url.netloc == "tinyurl.com":
        return phishing
    else:
        return legitimate


# 4
# 4.1.4 having_At_Symbol
def having_At_Symbol(url):
    print("###  having_At_Symbol: " + url + "  ####")
    if "@" in url:
        return phishing
    else:
        return legitimate


# 5
# 4.1.5 double_slash_redirecting
def double_slash_redirecting(url):
    print("###  double_slash_redirecting: " + url + "  ####")
    if "//" in url[7:]:
        return phishing
    else:
        return legitimate


# 6
# 4.1.6 Prefix_Suffix
def prefix_suffix(url):
    print("###  prefix_suffix " + url + "  ####")
    parsed_url = urlparse(url)
    if "-" in parsed_url.netloc:
        return phishing
    else:
        return legitimate


# 7
# 4.1.7 having_Sub_Domain
def having_Sub_Domain(url):
    print("###  having_Sub_Domain " + url + "  ####")
    parsed_url = urlparse(url)
    # The first dot after the “www” is omitted
    dot_number = parsed_url.netloc.count(".") - 1
    if dot_number == 1:
        return legitimate
    elif dot_number > 2:
        return phishing
    else:
        return suspicious


# 8
# 4.1.8 SSLfinal_State
def SSLfinal_State(url):
    print("###  SSLfinal_State: " + url + "  ####")
    parsed_url = urlparse(url)
    if parsed_url.scheme == "https":
        print("- url starts with https")

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.socket(), server_hostname=parsed_url.netloc
        ) as s:
            s.connect((parsed_url.netloc, 443))
            cert = s.getpeercert()
        subject = dict(x[0] for x in cert["subject"])
        issued_to = subject["commonName"]
        issuer = dict(x[0] for x in cert["issuer"])
        issuerOrganizationName = issuer["organizationName"]
        issued_by = issuer["commonName"]

        trustedOrgList = [
            "GeoTrust",
            "DigiCert Inc",
            "GoDaddy",
            "Network Solutions",
            "Thawte",
            "Comodo",
            "Doster",
            "VeriSign",
        ]
        if issuerOrganizationName in trustedOrgList:
            print("- Issued is in trusted list - " + issuerOrganizationName)

            # Calculate time
            seconds_since_epoch = time.time()
            # current_time = time.ctime(seconds_since_epoch)
            cert_exp_date = time.strptime(
                cert["notAfter"][:-4], "%b %d %H:%M:%S %Y"
            )  # convert to time format
            delta_in_sec = time.mktime(cert_exp_date) - seconds_since_epoch
            delta_in_years = delta_in_sec / 60 / 60 / 24 / 365.25

            if delta_in_years >= 1.0:
                print("- Cert exp date is >= 1 year")
                return legitimate
            else:
                print("- Cert exp date is < 1 year")
                return suspicious
        else:
            print("- Issued is not in trusted list - " + issuerOrganizationName)
            return suspicious
    else:
        print("- url doesn't start with https")
        return phishing


# 9
# 4.1.9 domain_registration_length
def domain_registration_length(url):
    print("###  domain_registration_length: " + url + "  ####")
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


# 10
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


# 11
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
            # TODO: Check why first call takes ~ 2 min
            result = s.connect_ex((host, port))
            if result == 0:
                print(f"Port is opened - {host}:{port}")
                return phishing
            print(f"Port is close - {host}:{port}")
    return legitimate


# 12
# 4.1.12 HTTPS_token
def https_token(url):
    print("###  https_token: " + url + "  ####")
    parsed_url = urlparse(url)
    if "https" in parsed_url.netloc:
        return phishing
    return legitimate


def tag(source_tag, get_tag, soup, url_netloc):
    tags = soup.find_all(source_tag)
    count = len(tags)  # if tag domain is empty it means the same domain
    phishing_count = 0
    for tag in tags:
        parsed_tag = urlparse(tag.get(get_tag))
        # print(f'{url_netloc}-{parsed_tag.netloc}')
        if parsed_tag.netloc and url_netloc != parsed_tag.netloc:
            phishing_count += 1
        if source_tag == "a" and (
            tag[get_tag].startswith("#")
            or tag[get_tag].startswith("javascript")
        ):
            phishing_count += 1
    return count, phishing_count


# 13
# 4.2.1 Request_URL
def request_url(url):
    print("###  request_url: " + url + "  ####")
    parsed_url = urlparse(url)
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    count_img, phishy_img_count = tag("img", "src", soup, parsed_url.netloc)
    count_source, phishy_source_count = tag(
        "source", "src", soup, parsed_url.netloc
    )
    count_audio, phishy_audio_count = tag(
        "audio", "src", soup, parsed_url.netloc
    )

    count_all = count_img + count_source + count_audio
    phishing_count = phishy_img_count + phishy_source_count + phishy_audio_count
    print(f"  count_all: {count_all}, phish_count: {phishing_count}")
    try:
        if phishing_count / count_all > 0.5:
            return phishing
    except:
        print("devision error")
        pass
    return legitimate


# 14
# 4.2.2 URL_of_Anchor
def url_of_anchor(url):
    print("###  url_of_anchor: " + url + "  ####")
    parsed_url = urlparse(url)
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    count_a, phishy_a_count = tag("a", "href", soup, parsed_url.netloc)

    print(f"  count_a: {count_a}, phish_count: {phishy_a_count}")
    try:
        result = phishy_a_count / count_a
        if result > 0.67:
            return phishing
        elif result <= 0.67 and result >= 0.31:
            return suspicious
    except:
        print("devision error")
        pass
    return legitimate


# 15
# 4.2.3 Links_in_tags
def links_in_tags(url):
    print("###  links_in_tags: " + url + "  ####")
    parsed_url = urlparse(url)
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    count_meta, phishy_meta_count = tag(
        "meta", "content", soup, parsed_url.netloc
    )
    count_script, phishy_script_count = tag(
        "script", "src", soup, parsed_url.netloc
    )
    count_link, phishy_link_count = tag("link", "href", soup, parsed_url.netloc)

    count_all = count_meta + count_script + count_link
    phishing_count = phishy_meta_count + phishy_script_count + phishy_link_count
    print(f"  count_all: {count_all}, phish_count: {phishing_count}")
    try:
        result = phishing_count / count_all
        if result > 0.81:
            return phishing
        elif result <= 0.81 and result >= 0.17:
            return suspicious
    except:
        print("devision error")
        pass
    return legitimate


# 16
# 4.2.4 SFH
def sfh(url):
    print("###  sfh: " + url + "  ####")
    parsed_url = urlparse(url)
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    tags = soup.find_all("form")
    for tag in tags:
        parsed_tag = urlparse(tag.get("action"))
        print(f"{parsed_url.netloc}-{parsed_tag.netloc}")
        if not parsed_tag.netloc and (
            parsed_tag.path == "" or parsed_tag.path == "about:blank"
        ):
            return phishing
        if parsed_tag.netloc and parsed_url.netloc != parsed_tag.netloc:
            return suspicious
    return legitimate


# 17
# 4.2.5 Submitting_to_email
def submitting_to_email(url):
    print("###  submitting_to_email: " + url + "  ####")
    parsed_url = urlparse(url)
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    tags = soup.find_all("form")
    for tag in tags:
        if tag["action"].startswith("mailto"):
            return phishing
    return legitimate


# 18
# 4.2.6 Abnormal_URL
def abnormal_url(url):
    print("###  abnormal_url: " + url + "  ####")
    parsed_url = urlparse(url)
    w = whois.whois(url)
    print(f"{parsed_url.netloc}-{w.domain_name}")
    if type(w.domain_name) == list:
        for domain in w.domain_name:
            if parsed_url.netloc.endswith(domain):
                return legitimate
    elif parsed_url.netloc.endswith(w.domain_name):
        return legitimate
    return phishing



# Test
print(having_Sub_Domain("https://www.google.co.il.ru"))
print(prefix_suffix("http://www.legi-timate.com"))
print(
    double_slash_redirecting(
        "http://www.legitimate.com//http://www.phishing.com"
    )
)
print(having_At_Symbol("https://tinyurl.com/4sbr2usn"))
print(shortining_Service("https://tinyurl.com/4sbr2usn"))
print(url_length(hostname))
print(having_ip_address(hostname))
print(SSLfinal_State("https://www.GeoTrust.com"))
print(domain_registration_length("https://www.google.com"))
print(check_favicon("https://www.github.com"))
print(check_favicon("https://www.python.org"))
print(open_ports("https://www.walla.com"))
print(https_token("http://https-www-paypal-it-webapps-home.soft-hair.com/"))
print(request_url("https://walla.com/"))
print(url_of_anchor("https://www.cisco.com"))
print(links_in_tags("https://www.cisco.com"))
print(sfh("https://www.walla.com"))
print(
    submitting_to_email(
        "https://www.w3schools.com/html/tryit.asp?filename=tryhtml_form_mail"
    )
)
print(abnormal_url("https://www.walla.co.il"))
