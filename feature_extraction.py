import pandas as pd
import re
import whois


# Calculate the number of months
def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month + d2.month


# Generate a new dataset from extracted features of the URL
def generate_data_set(url):
    # Convert the given url into standard format
    if not re.match(r"^https?", url):
        url = "http://" + url

    data = [url]
    df = pd.DataFrame(data)
    # Separates the protocol and domain from the string and adds it to a column
    refinedDataset = df[0].str.split("://|/", 2, expand=True)
    refinedDataset.columns = ['Protocol', 'Domain', 'Address']
    print(refinedDataset)

    # The next step is feature extraction. Three metrics will be used for this classification and given values for
    # identification Legitimate - 0, Phishing - 1 The classification "Suspicious" is introduced to identify URLs that
    # cannot be confirmed by this program as a phishing URL Starting with the occurrence of the @ symbol

    # 1 Does the URl contain an @ symbol
    def contain_at_sym(a):
        """This function is defined to check if the URL has an @ symbol or not"""
        if "@" in str(a):
            return 1
        return 0

    # 2 Identify unusually long urls
    def long_url(l):
        if len(str(l)) < 80:
            return 0
        elif 80 <= len(str(l)) <= 2048:
            return 2
        return 1

    # 3 Finds the occurrence of //
    def redirect(r):
        if "//" in str(r):
            return 1
        return 0

    # 4 Subdomains and domains
    # If the number of dots is greater than 3, the likelihood of the URL being malicious is high
    def sub_domain(s):
        if str(s).count('.') < 3:
            return 0
        if str(s).count('.') == 3:
            return 1

    # 5 Finding if the URL has an IP address
    def has_ip_addr(u):
        match = re.search(
            '(([01]?\\\\d\\\\d?|2[0-4]\\\\d|25[0-5])\\\\.([01]?\\\\d\\\\d?|2[0-4]\\\\d|25[0-5])\\\\.([01]?\\\\d\\\\d?|2[0-4]\\\\d|25[0-5])\\\\.([01]?\\\\d\\\\d?|2[0-4]\\\\d|25[0-5])\\\\/)|'  # IPv4,
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 
            # Hexadecimal , 
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', str(u))  # IPv6

        if match:
            # print it matches the group()
            return 1
        else:
            # print No match has been found
            return 0

    # 6 URL is made considerably shorter
    def shorten_service(v):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',
                          str(v))

        if match:
            return 1
        else:
            return 0

    # The minimum age of legitimate domains are 6 months
    def age_of_domain_sub(domain):
        creation_date = domain.creation_date
        expiration_date = domain.expiration_date
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 2
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain / 30) < 6):
                return 1
            else:
                return 0

    def age_of_domain_main(domain):
        global domain_name, Url
        dns = 0
        try:
            domain_name = whois.whois(domain)
        except:
            dns = 1

        if dns == 1:
            return 1
        else:
            return age_of_domain_sub(domain_name)

    # Apply the function to dataset then add the values to a column in the dataset
    refinedDataset['has_@_symbol'] = df.apply(contain_at_sym)
    refinedDataset['long_url'] = df.apply(long_url)
    refinedDataset['redirect_for_//'] = refinedDataset['Protocol'].apply(redirect)
    refinedDataset['sub_domain'] = refinedDataset['Domain'].apply(sub_domain)
    refinedDataset['has_IP_addr'] = df.apply(has_ip_addr)
    refinedDataset['shorten_service'] = df.apply(shorten_service)
    refinedDataset['age_of_domain'] = refinedDataset['Domain'].apply(age_of_domain_main)

    # Removing unnecessary columns
    model_data = refinedDataset.drop(refinedDataset.columns[[0, 1, 2]], axis=1)
    print(model_data)
    return model_data
