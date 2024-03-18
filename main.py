import csv
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
import random
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
    logging.info("having_ip_address: " + url)
    parsed_url = urlparse(url)
    try:
        netaddr.IPAddress(parsed_url.netloc)
        return phishing
    except Exception as e:
        logging.error(f" - {e} = legitimate")
        return legitimate


# 2
# 4.1.2 URL_Length
def url_length(url):
    logging.info("URL_Length: " + url)
    return len(url)


# 3
# 4.1.3 Shortining_Service
def shortining_Service(url):
    logging.info("shortining_Service: " + url)
    parsed_url = urlparse(url)
    if parsed_url.netloc == "tinyurl.com":
        return phishing
    else:
        return legitimate


# 4
# 4.1.4 Count_at_Symbol
def having_At_Symbol(url):
    logging.info("having_At_Symbol: " + url)
    return url.count("@")


# 5
# 4.1.5 double_slash_redirecting
def double_slash_redirecting(url):
    logging.info("double_slash_redirecting: " + url)
    return url[7:].count("//")

# 6
# 4.1.6 Prefix_Suffix
def prefix_suffix(url):
    logging.info("prefix_suffix " + url)
    parsed_url = urlparse(url)
    return parsed_url.netloc.count("-")


# 7
# 4.1.7 having_Sub_Domain
def having_Sub_Domain(url):
    logging.info("having_Sub_Domain " + url)
    parsed_url = urlparse(url)
    # The first dot after the “www” is omitted
    return parsed_url.netloc.count(".") - 1


# 8
# 4.1.8 SSLfinal_State
def SSLfinal_State(url):
    logging.info("SSLfinal_State: " + url)
    parsed_url = urlparse(url)
    # Return none for no certification
    cert = "None"
    if parsed_url.scheme == "https":
        logging.info(" - url starts with https")

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=parsed_url.netloc) as s:
            s.connect((parsed_url.netloc, 443))
            cert = s.getpeercert()
    return cert


# 9
# 4.1.9 domain_registration_length
def domain_registration_length(url):
    logging.info("domain_registration_length: " + url)
    w = "None"
    try:
        w = whois.whois(url)
    except Exception as e:
        logging.error(e)
    return w


# 10
# 4.1.10 Favicon
def check_favicon(url):
    logging.info("check_favicon: " + url)
    try:
        icons = favicon.get(url, timeout=20)  # 20 sec timeout
        parsed_url = urlparse(url)
        for icon in icons:
            parsed_icon = urlparse(icon.url)
            # logging.info(parsed_icon.netloc)
            # logging.info(parsed_url.netloc)
            if parsed_icon.netloc != parsed_url.netloc:
                return phishing
        return legitimate
    # Failure = legitimate
    except Exception as e:
        logging.error(e)
        return legitimate


# 11
# 4.1.11 port
def open_ports(url):
    logging.info("open_ports: " + url)
    parsed_url = urlparse(url)
    port_list = [21, 22, 23, 445, 1433, 1521, 3306, 3389]
    opened_ports = []
    host = socket.gethostbyname(parsed_url.netloc)
    logging.info(host)
    for port in port_list:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            socket.setdefaulttimeout(1)
            # TODO: Check why first call takes ~ 2 min
            result = s.connect_ex((host, port))
            if result == 0:
                logging.info(f" - Port is opened - {host}:{port}")
                opened_ports.append(port)
            logging.info(f" - Port is closed - {host}:{port}")
    return opened_ports


# 12
# 4.1.12 HTTPS_token
def https_token(url):
    logging.info("https_token: " + url)
    parsed_url = urlparse(url)
    if "https" in parsed_url.netloc:
        return phishing
    return legitimate

# help function
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
        try:
            if source_tag == "a" and (
                tag[get_tag].startswith("#") or tag[get_tag].startswith("javascript")
            ):
                phishing_count += 1
        except Exception as e:
            logging.error(e)
            pass
    return count, phishing_count


# 13
# 4.2.1 Request_URL
def request_url(url):
    logging.info("request_url: " + url)
    parsed_url = urlparse(url)
    home_page = requests.get(url, timeout=20, verify=False)
    soup = BeautifulSoup(home_page.content, "html.parser")
    count_img, phishy_img_count = tag("img", "src", soup, parsed_url.netloc)
    count_source, phishy_source_count = tag("source", "src", soup, parsed_url.netloc)
    count_audio, phishy_audio_count = tag("audio", "src", soup, parsed_url.netloc)

    count_all = count_img + count_source + count_audio
    phishing_count = phishy_img_count + phishy_source_count + phishy_audio_count
    logging.info(f" - count_all: {count_all}, phish_count: {phishing_count}")
    try:
        return (phishing_count / count_all)
    except Exception as e:
        logging.error(f" - devision error - {e}")
        return 0


# 14
# 4.2.2 URL_of_Anchor
def url_of_anchor(url):
    logging.info("url_of_anchor: " + url)
    parsed_url = urlparse(url)
    home_page = requests.get(url, timeout=20, verify=False)
    soup = BeautifulSoup(home_page.content, "html.parser")

    count_a, phishy_a_count = tag("a", "href", soup, parsed_url.netloc)
    logging.info(f"  count_a: {count_a}, phish_count: {phishy_a_count}")
    try:
        return (phishy_a_count / count_a)
    except Exception as e:
        logging.error(f" - devision error - {e}")
        return 0


# 15
# 4.2.3 Links_in_tags
def links_in_tags(url):
    logging.info("links_in_tags: " + url)
    parsed_url = urlparse(url)
    home_page = requests.get(url, timeout=20, verify=False)
    soup = BeautifulSoup(home_page.content, "html.parser")
    count_meta, phishy_meta_count = tag("meta", "content", soup, parsed_url.netloc)
    count_script, phishy_script_count = tag("script", "src", soup, parsed_url.netloc)
    count_link, phishy_link_count = tag("link", "href", soup, parsed_url.netloc)

    count_all = count_meta + count_script + count_link
    phishing_count = phishy_meta_count + phishy_script_count + phishy_link_count
    logging.info(f" - count_all: {count_all}, phish_count: {phishing_count}")
    try:
        return (phishing_count / count_all)
    except Exception as e:
        logging.error(f" - devision error - {e}")
        return 0


# 16
# 4.2.4 SFH
def sfh(url):
    logging.info("sfh: " + url)
    parsed_url = urlparse(url)
    home_page = requests.get(url, timeout=20, verify=False)
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
    logging.info("submitting_to_email: " + url)
    home_page = requests.get(url, timeout=20, verify=False)
    soup = BeautifulSoup(home_page.content, "html.parser")

    tags = soup.find_all("form")
    for tag in tags:
        if tag["action"].startswith("mailto"):
            return phishing
    return legitimate


# 18
# 4.2.6 Abnormal_URL
def abnormal_url(url):
    logging.info("abnormal_url: " + url)
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
    logging.info("redirect: " + url)
    r = requests.get(url, timeout=20, verify=False)
    logging.info(r.history)
    return r.history


# 20
# 4.3.2 on_mouseover
def on_mouseover(url):
    logging.info("on_mouseover: " + url)
    home_page = requests.get(url, timeout=20, verify=False)
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
    logging.info("right_click: " + url)
    home_page = requests.get(url, timeout=20, verify=False)
    right_click_event = re.findall(r"event.button ?== ?2", home_page.text)
    if right_click_event:
        return phishing
    return legitimate


# 22
# 4.3.4 popUpWidnow
def popUpWidnow(url):
    logging.info("popUpWidnow: " + url)
    home_page = requests.get(url, timeout=20, verify=False)
    # Checks only window popup and not window popup with a form
    popup_win = re.findall(r"window.open", home_page.text)
    if popup_win:
        return phishing
    return legitimate


# 23
# 4.3.5 Iframe
def Iframe(url):
    logging.info("Iframe: " + url)
    home_page = requests.get(url, timeout=20, verify=False)
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
    logging.info("age_of_domain: " + url)
    now = datetime.now()
    try:
        w = whois.whois(url)
        if type(w.creation_date) == list:
            domain_creation_date = w.creation_date[0]
        else:
            domain_creation_date = w.creation_date
        time_delta = now - domain_creation_date
        return time_delta.days
    except Exception as e:
        logging.error(e)
        return 0


# 25
# 4.4.2 DNSRecord
def DNSRecord(url):
    logging.info("DNSRecord: " + url)
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
    logging.info("web_traffic: " + url)
    home_page = requests.get(
        "http://data.alexa.com/data?cli=10&dat=s&url=" + url, timeout=20, verify=False
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
    logging.info("google_index: " + url)
    query = f"site:{url}"
    params = {"q": query}
    response = requests.get("https://www.google.com/search", params=params, timeout=20, verify=False)

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
#     response = requests.get(url, timeout=20, verify=False)

#     if response.status_code == 200:
#         soup = BeautifulSoup(response.content, "html.parser")
#         logging.info(soup)


# Collect legitimate URLs using google search for randomized words
def collect_urls():
    words = []
    urls = []
    words_num = 25

    logging.info(f"######### Start for {words_num} words #########")
    r = RandomWords()
    words = [r.get_random_word() for i in range(words_num)]

    sentences = []
    for n in range(15):
        # Generate list, each item with two words
        sentences.append(' '.join([words[random.randint(0,len(words)-1)] for i in range(2)]))
    print(sentences)

    urls = set()
    with open("URLs.txt", "a") as f:
        for s in sentences:
            w_urls = set(search(s, num_results=10))
            urls.update(w_urls)
            for url in w_urls:
                f.write("%s\n" % url)
            # workaround for 429 Client Error: Too Many Requests for url
            time.sleep(300)

    logging.info("######### End #########")
    logging.info("####  collect_urls - collected {} URLS ####".format(len(urls)))



def get_list_features(url):
    features_list = []

    features_list.append(having_ip_address(url))
    features_list.append(url_length(url))
    features_list.append(shortining_Service(url))
    features_list.append(having_At_Symbol(url))
    features_list.append(double_slash_redirecting(url))
    features_list.append(prefix_suffix(url))
    features_list.append(having_Sub_Domain(url))
    features_list.append(SSLfinal_State(url))
    features_list.append(domain_registration_length(url))
    features_list.append(check_favicon(url))
    features_list.append(open_ports(url))
    features_list.append(https_token(url))
    features_list.append(request_url(url))
    features_list.append(url_of_anchor(url))
    features_list.append(links_in_tags(url))
    features_list.append(sfh(url))
    features_list.append(submitting_to_email(url))
    features_list.append(abnormal_url(url))
    features_list.append(redirect(url))
    features_list.append(on_mouseover(url))
    features_list.append(right_click(url))
    features_list.append(popUpWidnow(url))
    features_list.append(Iframe(url))
    features_list.append(age_of_domain(url))
    features_list.append(DNSRecord(url))
    # Disabling web_traffic feature as data.alexa.com is went down
    # features_list.append(web_traffic(url))
    features_list.append(google_index(url))

    return features_list


def create_df():
    import pandas as pd

    df_columns = [
        "having_IP_Address",
        "URL_Length",
        "Shortining_Service",
        "having_At_Symbol",
        "double_slash_redirecting",
        "Prefix_Suffix",
        "having_Sub_Domain",
        "SSLfinal_State",
        "Domain_registeration_length",
        "Favicon",
        "port",
        "HTTPS_token",
        "Request_URL",
        "URL_of_Anchor",
        "Links_in_tags",
        "SFH",
        "Submitting_to_email",
        "Abnormal_URL",
        "Redirect",
        "on_mouseover",
        "RightClick",
        "popUpWidnow",
        "Iframe",
        "age_of_domain",
        "DNSRecord",
        # Disabling web_traffic feature as data.alexa.com is went down
        # 'web_traffic',
        "Google_Index",
        "Result",
    ]
    df = pd.DataFrame(columns=df_columns)
    url = "https://investopedia.com/terms/i/incontestability-clause.asp"
    features_list = get_list_features(url)

    features_list.append(1) if url in phishing_list else features_list.append(
        0
    )  # add phishing or legitimate to result

    df.loc[len(df)] = features_list
    print(df)


def get_urls_list_features(urls, url_type, writer):
    id = 1
    skipped = 0
    for url in urls:
        feature_list = []
        feature_list.append(id)
        feature_list.append(url)
        try:
            feature_list += get_list_features(url)
            id += 1
            feature_list.append(url_type)
            logging.info(f"### {url} - {feature_list} ###")
            writer.writerow(feature_list)
        except Exception as e:
            logging.error(e)
            skipped += 1
            logging.info(f"\n****************  Skipping - {url}   ****************\n")
        total = id + skipped
        logging.info(f"\n****************  Skipped: {skipped} From: {total}  ****************\n")


def create_csv():
    header = [
        "id",
        "url",
        "having_IP_Address", #1
        "URL_Length", #2
        "Shortining_Service", #3
        "having_At_Symbol", #4
        "double_slash_redirecting", #5
        "Prefix_Suffix", #6
        "having_Sub_Domain", #7
        "SSLfinal_State", #8
        "Domain_registeration_length", #9
        "Favicon", #10
        "port", #11
        "HTTPS_token", #12
        "Request_URL", #13
        "URL_of_Anchor", #14
        "Links_in_tags", #15
        "SFH", #16
        "Submitting_to_email", #17
        "Abnormal_URL", #18
        "Redirect", #19
        "on_mouseover", #20
        "RightClick", #21
        "popUpWidnow", #22
        "Iframe", #23
        "age_of_domain", #24
        "DNSRecord", #25
        # "web_traffic",
        "Google_Index", #26
        "Result",
    ]
    with open(
        "dynamic_dataset.csv", "a", encoding="UTF8", newline="", buffering=1
    ) as f:
        writer = csv.writer(f)
        writer.writerow(header)

        # Update csv file for each legitimate URL
        # legit_url_file = open("URLs.txt", "r")
        # legit_urls = legit_url_file.readlines()
        # get_urls_list_features(legit_urls,legitimate,writer)

        # Update csv file for each phishing URL
        phishing_url_file = open("march-17-phishing-urls.txt", "r")
        phishing_urls = phishing_url_file.readlines()
        get_urls_list_features(phishing_urls,phishing,writer)


# Verification
def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(message)s",
        datefmt="%d-%b-%y %H:%M:%S",
        handlers=[logging.FileHandler("debug.log", mode="a"), logging.StreamHandler()],
    )
    create_csv()
    # create_df()
    # collect_urls()
    # logging.info(having_Sub_Domain("https://www.google.co.il.ru"))
    # logging.info(prefix_suffix("http://www.legi-timate.com"))
    # logging.info(
    #     double_slash_redirecting(
    #         "http://www.legitimate.com//http://www.phishing.com"
    #     )
    # )
    # logging.info(having_At_Symbol("https://tinyurl.com/4sbr2usn"))
    # logging.info(shortining_Service("https://tinyurl.com/4sbr2usn"))
    # logging.info(url_length("https://www.google.com/"))
    # logging.info(having_ip_address("https://www.google.com/"))
    # logging.info(SSLfinal_State("https://alareentading-catalog.page.tl/"))

    # logging.info(SSLfinal_State("https://www.GeoTrust.com"))
    # logging.info(domain_registration_length("https://www.google.com"))
    # logging.info(check_favicon("https://www.tripadvisor.com/ShowUserReviews-g1152699-d6148508-r590504727-Ye_Shi_Fermented_Egg-Kinmen.html"))
    # logging.info(check_favicon("https://www.investopedia.com/terms/i/incontestability-clause.asp"))
    # logging.info(open_ports("https://www.walla.com"))
    # logging.info(
    #     https_token("http://https-www-paypal-it-webapps-home.soft-hair.com/")
    # )
    # logging.info(request_url("https://www.investopedia.com/terms/i/incontestability-clause.asp"))
    # logging.info(url_of_anchor("https://www.walla.com"))
    # logging.info(links_in_tags("https://www.cisco.com"))
    # logging.info(sfh("https://www.walla.com"))
    # logging.info(
    #     submitting_to_email(
    #         "https://www.w3schools.com/html/tryit.asp?filename=tryhtml_form_mail"
    #     )
    # )
    # logging.info(abnormal_url("https://www.walla.co.il"))
    # logging.info(redirect("https://www.walla.com"))
    # logging.info(
    #     on_mouseover(
    #         "https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_onmouseover"
    #     )
    # )
    # logging.info(
    #     right_click(
    #         "https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_onmouseover"
    #     )
    # )
    # logging.info(
    #     popUpWidnow(
    #         "https://www.w3schools.com/jsref/tryit.asp?filename=tryjsref_win_open"
    #     )
    # )
    # logging.info(
    #     Iframe(
    #         "https://www.w3schools.com/html/tryit.asp?filename=tryhtml_iframe_frameborder"
    #     )
    # )
    # logging.info(age_of_domain("https://www.walla.com"))
    # logging.info(DNSRecord("https://www.walla.co.il"))
    # logging.info(web_traffic("https://www.galit.co.il"))
    # logging.info(google_index("https://www.google.com"))


if __name__ == "__main__":
    main()
