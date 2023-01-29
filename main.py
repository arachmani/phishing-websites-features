import logging
import re
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
from googlesearch import search
from random_word import RandomWords

legitimate = 1
suspicious = 0
phishing = -1

# 1
# 4.1.1 having_IP_Address:
def having_ip_address(url):
    logging.info("###  having_ip_address: " + url + "  ####")
    parsed_url = urlparse(url)
    try:
        netaddr.IPAddress(parsed_url.netloc)
        return phishing
    except:
        return legitimate


# 2
# 4.1.2 URL_Length
def url_length(url):
    logging.info("###  URL_Length: " + url + "  ####")
    if len(url) < 54:
        return legitimate
    elif len(url) > 75:
        return phishing
    else:
        suspicious


# 3
# 4.1.3 Shortining_Service
def shortining_Service(url):
    logging.info("###  shortining_Service: " + url + "  ####")
    parsed_url = urlparse(url)
    if parsed_url.netloc == "tinyurl.com":
        return phishing
    else:
        return legitimate


# 4
# 4.1.4 having_At_Symbol
def having_At_Symbol(url):
    logging.info("###  having_At_Symbol: " + url + "  ####")
    if "@" in url:
        return phishing
    else:
        return legitimate


# 5
# 4.1.5 double_slash_redirecting
def double_slash_redirecting(url):
    logging.info("###  double_slash_redirecting: " + url + "  ####")
    if "//" in url[7:]:
        return phishing
    else:
        return legitimate


# 6
# 4.1.6 Prefix_Suffix
def prefix_suffix(url):
    logging.info("###  prefix_suffix " + url + "  ####")
    parsed_url = urlparse(url)
    if "-" in parsed_url.netloc:
        return phishing
    else:
        return legitimate


# 7
# 4.1.7 having_Sub_Domain
def having_Sub_Domain(url):
    logging.info("###  having_Sub_Domain " + url + "  ####")
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
    logging.info("###  SSLfinal_State: " + url + "  ####")
    parsed_url = urlparse(url)
    if parsed_url.scheme == "https":
        logging.info("- url starts with https")

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
            logging.info(
                "- Issued is in trusted list - " + issuerOrganizationName
            )

            # Calculate time
            seconds_since_epoch = time.time()
            # current_time = time.ctime(seconds_since_epoch)
            cert_exp_date = time.strptime(
                cert["notAfter"][:-4], "%b %d %H:%M:%S %Y"
            )  # convert to time format
            delta_in_sec = time.mktime(cert_exp_date) - seconds_since_epoch
            delta_in_years = delta_in_sec / 60 / 60 / 24 / 365.25

            if delta_in_years >= 1.0:
                logging.info("- Cert exp date is >= 1 year")
                return legitimate
            else:
                logging.info("- Cert exp date is < 1 year")
                return suspicious
        else:
            logging.info(
                "- Issued is not in trusted list - " + issuerOrganizationName
            )
            return suspicious
    else:
        logging.info("- url doesn't start with https")
        return phishing


# 9
# 4.1.9 domain_registration_length
def domain_registration_length(url):
    logging.info("###  domain_registration_length: " + url + "  ####")
    now = datetime.now()
    try:
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
    except Exception as e:
        logging.error(e)
        return phishing


# 10
# 4.1.10 Favicon
def check_favicon(url):
    logging.info("###  check_favicon: " + url + "  ####")
    icons = favicon.get(url)
    parsed_url = urlparse(url)
    for icon in icons:
        parsed_icon = urlparse(icon.url)
        # logging.info(parsed_icon.netloc)
        # logging.info(parsed_url.netloc)
        if parsed_icon.netloc != parsed_url.netloc:
            return phishing
    return legitimate


# 11
# 4.1.11 port
def open_ports(url):
    logging.info("###  open_ports: " + url + "  ####")
    parsed_url = urlparse(url)
    port_list = [21, 22, 23, 445, 1433, 1521, 3306, 3389]
    host = socket.gethostbyname(parsed_url.netloc)
    logging.info(host)
    for port in port_list:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)
            # TODO: Check why first call takes ~ 2 min
            result = s.connect_ex((host, port))
            if result == 0:
                logging.info(f"Port is opened - {host}:{port}")
                return phishing
            logging.info(f"Port is close - {host}:{port}")
    return legitimate


# 12
# 4.1.12 HTTPS_token
def https_token(url):
    logging.info("###  https_token: " + url + "  ####")
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
        # logging.info(f'{url_netloc}-{parsed_tag.netloc}')
        if parsed_tag.netloc and url_netloc != parsed_tag.netloc:
            phishing_count += 1

        # For url_of_anchor # 14
        if source_tag == "a" and (
            tag[get_tag].startswith("#")
            or tag[get_tag].startswith("javascript")
        ):
            phishing_count += 1
    return count, phishing_count


# 13
# 4.2.1 Request_URL
def request_url(url):
    logging.info("###  request_url: " + url + "  ####")
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
    logging.info(f"  count_all: {count_all}, phish_count: {phishing_count}")
    try:
        if phishing_count / count_all > 0.5:
            return phishing
    except:
        logging.error("devision error")
        pass
    return legitimate


# 14
# 4.2.2 URL_of_Anchor
def url_of_anchor(url):
    logging.info("###  url_of_anchor: " + url + "  ####")
    parsed_url = urlparse(url)
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    count_a, phishy_a_count = tag("a", "href", soup, parsed_url.netloc)

    logging.info(f"  count_a: {count_a}, phish_count: {phishy_a_count}")
    try:
        result = phishy_a_count / count_a
        if result > 0.67:
            return phishing
        elif result <= 0.67 and result >= 0.31:
            return suspicious
    except:
        logging.error("devision error")
        pass
    return legitimate


# 15
# 4.2.3 Links_in_tags
def links_in_tags(url):
    logging.info("###  links_in_tags: " + url + "  ####")
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
    logging.info(f"  count_all: {count_all}, phish_count: {phishing_count}")
    try:
        result = phishing_count / count_all
        if result > 0.81:
            return phishing
        elif result <= 0.81 and result >= 0.17:
            return suspicious
    except:
        logging.error("devision error")
        pass
    return legitimate


# 16
# 4.2.4 SFH
def sfh(url):
    logging.info("###  sfh: " + url + "  ####")
    parsed_url = urlparse(url)
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    tags = soup.find_all("form")
    for tag in tags:
        parsed_tag = urlparse(tag.get("action"))
        logging.info(f"{parsed_url.netloc}-{parsed_tag.netloc}")
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
    logging.info("###  submitting_to_email: " + url + "  ####")
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
    logging.info("###  abnormal_url: " + url + "  ####")
    parsed_url = urlparse(url)
    try:
        w = whois.whois(url)
        logging.info(f"{parsed_url.netloc}-{w.domain_name}")
        if type(w.domain_name) == list:
            for domain in w.domain_name:
                if parsed_url.netloc.endswith(domain):
                    return legitimate
        elif parsed_url.netloc.endswith(w.domain_name):
            return legitimate
        return phishing
    except Exception as e:
        logging.error(e)
        return phishing


# 19
# 4.3.1 Redirect
def redirect(url):
    logging.info("###  redirect: " + url + "  ####")
    r = requests.get(url)
    logging.info(r.history)
    if len(r.history) > 1:
        return suspicious
    else:
        return legitimate


# 20
# 4.3.2 on_mouseover
def on_mouseover(url):
    logging.info("###  on_mouseover: " + url + "  ####")
    home_page = requests.get(url)
    # window.defaultStatus/window.status should be used for changing the status bar
    # onMouseOver must use one of them directly or via JavaScript
    w_status = re.findall(r"window.status", home_page.text)
    w_default_status = re.findall(r"window.defaultStatus", home_page.text)
    if w_status or w_default_status:
        return phishing
    return legitimate


# 21
# 4.3.3 RightClick
def right_click(url):
    logging.info("###  right_click: " + url + "  ####")
    home_page = requests.get(url)
    right_click_event = re.findall(r"event.button ?== ?2", home_page.text)
    if right_click_event:
        return phishing
    return legitimate


# 22
# 4.3.4 popUpWidnow
def popUpWidnow(url):
    logging.info("###  popUpWidnow: " + url + "  ####")
    home_page = requests.get(url)
    # Checks only window popup and not window popup with a form
    popup_win = re.findall(r"window.open", home_page.text)
    if popup_win:
        return phishing
    return legitimate


# 23
# 4.3.5 Iframe
def Iframe(url):
    logging.info("###  Iframe: " + url + "  ####")
    home_page = requests.get(url)
    soup = BeautifulSoup(home_page.content, "html.parser")

    # frameBorder is deprected in html5
    frameBorders = soup.find_all("iframe", {"frameBorder": "0"})
    borders = soup.find_all("iframe", {"style": "border:none;"})
    borders = borders + soup.find_all("iframe", {"style": "border:0;"})
    if frameBorders or borders:
        return phishing
    return legitimate


# 24
# 4.4.1 age_of_domain
def age_of_domain(url):
    logging.info("###  age_of_domain: " + url + "  ####")
    now = datetime.now()
    try:
        w = whois.whois(url)
        if type(w.creation_date) == list:
            domain_creation_date = w.creation_date[0]
        else:
            domain_creation_date = w.creation_date
        time_delta = now - domain_creation_date
        if time_delta.days > 30 * 6:  # 30*6 = ~6 months
            return legitimate
        else:
            return phishing
    except Exception as e:
        logging.error(e)
        return phishing


# 25
# 4.4.2 DNSRecord
def DNSRecord(url):
    logging.info("###  DNSRecord: " + url + "  ####")
    try:
        w = whois.whois(url)
        if w.name_servers:
            return legitimate
        else:
            return phishing
    except Exception as e:
        logging.error(e)
        return phishing


# 26
# 4.4.3 web_traffic
def web_traffic(url):
    logging.info("###  web_traffic: " + url + "  ####")
    home_page = requests.get(
        "http://data.alexa.com/data?cli=10&dat=s&url=" + url
    )
    pattern = r'REACH RANK="(.*?)"/'
    match = re.search(pattern, home_page.text)

    if match:
        url_alexa_rank = int(match.group(1))
        if url_alexa_rank < 100000:
            return legitimate
        else:
            return suspicious
    return phishing


# 27
# 4.4.4 Page_Rank
# google rank page is not exposed


# 28
# 4.4.5 Google_Index
def google_index(url):
    logging.info("###  google_index: " + url + "  ####")
    query = f"site:{url}"
    params = {"q": query}
    response = requests.get("https://www.google.com/search", params=params)

    if response.status_code == 200:
        if "No results found for" in response.text:
            return phishing
        else:
            return legitimate
    else:
        return phishing


# 29
# 4.4.6 Links_pointing_to_page
# Need to own the site or use none free tools


# 30
# 4.4.7 Statistical_report
# Seems like there are no new reports from the last months on phishtank.
# StopBadware stopped working around 2021 because of copyright restrictions.
# def statistical_report():
#     import pandas as pd

#     year = "2017"
#     month = "01"
#     url = f"https://phishtank.org/stats/{year}/{month}/"
#     response = requests.get(url)

#     if response.status_code == 200:
#         soup = BeautifulSoup(response.content, "html.parser")
#         logging.info(soup)


# Verification
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
    )
    logging.info(having_Sub_Domain("https://www.google.co.il.ru"))
    logging.info(prefix_suffix("http://www.legi-timate.com"))
    logging.info(
        double_slash_redirecting(
            "http://www.legitimate.com//http://www.phishing.com"
        )
    )
    logging.info(having_At_Symbol("https://tinyurl.com/4sbr2usn"))
    logging.info(shortining_Service("https://tinyurl.com/4sbr2usn"))
    logging.info(url_length("https://www.google.com/"))
    logging.info(having_ip_address("https://www.google.com/"))
    logging.info(SSLfinal_State("https://www.GeoTrust.com"))
    logging.info(domain_registration_length("https://www.google.com"))
    logging.info(check_favicon("https://www.github.com"))
    logging.info(check_favicon("https://www.python.org"))
    logging.info(open_ports("https://www.walla.com"))
    logging.info(
        https_token("http://https-www-paypal-it-webapps-home.soft-hair.com/")
    )
    logging.info(request_url("https://walla.com/"))
    logging.info(url_of_anchor("https://www.cisco.com"))
    logging.info(links_in_tags("https://www.cisco.com"))
    logging.info(sfh("https://www.walla.com"))
    logging.info(
        submitting_to_email(
            "https://www.w3schools.com/html/tryit.asp?filename=tryhtml_form_mail"
        )
    )
    logging.info(abnormal_url("https://www.walla.co.il"))
    logging.info(redirect("https://www.walla.com"))
    logging.info(
        on_mouseover(
            "https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_onmouseover"
        )
    )
    logging.info(
        right_click(
            "https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_onmouseover"
        )
    )
    logging.info(
        popUpWidnow(
            "https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_win_open"
        )
    )
    logging.info(
        Iframe(
            "https://www.w3schools.com/html/tryit.asp?filename=tryhtml_iframe_frameborder"
        )
    )
    logging.info(age_of_domain("https://www.walla.com"))
    logging.info(DNSRecord("https://www.walla.co.il"))
    logging.info(web_traffic("https://www.galit.co.il"))
    logging.info(google_index("https://www.google.com"))


if __name__ == "__main__":
    main()
