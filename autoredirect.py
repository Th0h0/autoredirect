import regex
import argparse
import requests
import os
import threading


currentPath = os.path.dirname(__file__)
os.chdir(currentPath)

CANARY_TEXT = 'CANARY049'
CANARY_DOMAIN = 'canaryredirect.fr'
FUZZ_PLACE_HOLDER = '??????'
TIMEOUT_DELAY = 1.75
LOCK = threading.Lock()

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=False, help= 'file of all URLs to be tested against Open Redirect')
parser.add_argument("--url", "-u", type=str, required=False, help= 'url to be tested against Open Redirect')
parser.add_argument("--threads", "-n", type=int, required=False, help= 'number of threads for the tool')
parser.add_argument("--verbose", "-v", action='store_true', help='activate verbose mode for the tool')
parser.add_argument("--smart", "-s", action='store_true', help='activate context-based payload generation for each tested URL')
parser.add_argument("--oneshot", "-t", action='store_true', help='fuzz with only one basic payload - to be activated in case of time constraints')
parser.add_argument("--output", "-o", action='store_true', help='output file path')

args = parser.parse_args()

if not (args.file or args.url):
    parser.error('No input selected: Please add --file or --url as arguments.')

if args.smart and args.oneshot:
    parser.error('Incompatible modes chosen : oneshot mode implies that only one payload is used.')

defaultPayloadFile = open("default-payloads.txt", "r")

if args.oneshot:
    payloads = [f"http://{CANARY_DOMAIN}"]
else:
    payloads = [payload.replace('\n', '') for payload in defaultPayloadFile]


if args.file :
    allURLs = [line.replace('\n','') for line in open(args.file, "r")]

regexMultipleParams = '(?<=(Url|URL|Open|callback|checkout|continue|data|dest|destination|dir|domain|feed|file|file_name|folder|forward|go|goto|host|html|load_file|login\?to|logout|navigation|next|next_page|out|page|path|port|redir|redirect|redirect_to|uri|URI|Uri|reference|return|returnTo|return_path|return_to|show|site|target|to|url|val|validate|view|window)=)(.*)(?=&)'

regexSingleParam = '(?<=(Url|URL|Open|callback|checkout|continue|data|dest|destination|dir|domain|feed|file|file_name|folder|forward|go|goto|host|html|load_file|login\?to|logout|navigation|next|next_page|out|page|path|port|redir|redirect|redirect_to|uri|URI|Uri|reference|return|returnTo|return_path|return_to|show|site|target|to|url|val|validate|view|window)=)(.*)'

if args.output:
    output = open(args.output, "w")
else:
    output = open("open-redirect-output.txt", "w")


def splitURLS(threadsSize): #Multithreading

    splitted = []
    URLSsize = len(allURLs)
    width = int(URLSsize/threadsSize)
    if width == 0:
        width = 1
    endVal = 0
    i = 0
    while endVal != URLSsize:
        if URLSsize <= i + 2 * width:
            if len(splitted) == threadsSize - 2:
                endVal = int(i + (URLSsize - i)/2)
            else:
                endVal = URLSsize
        else:
            endVal = i + width

        splitted.append(allURLs[i: endVal])
        i += width

    return splitted

def exception_verbose_message(exceptionType):
    if args.verbose:
        if exceptionType == "timeout":
            print("\nTimeout detected... URL skipped")
        elif exceptionType == "redirects":
            print("\nToo many redirects... URL skipped")
        elif exceptionType == "others":
            print("\nRequest error... URL skipped")

def smart_extract_host(url, matchedElement):
    urlDecodedElem = requests.utils.unquote(matchedElement)
    hostExtractorRegex = '(?<=(https|http):\/\/)(.*?)(?=\/)'
    extractedHost = regex.search(hostExtractorRegex, urlDecodedElem)
    if not extractedHost:
        extractedHost = regex.search(hostExtractorRegex, url)

    return extractedHost.group()

def generate_payloads(whitelistedHost):
    generated =[
    f"http://{whitelistedHost}.{CANARY_DOMAIN}",       # whitelisted.attacker.com
    f"http://{CANARY_DOMAIN}?{whitelistedHost}",
    f"http://{CANARY_DOMAIN}/{whitelistedHost}",
    f"http://{CANARY_DOMAIN}%ff@{whitelistedHost}",
    f"http://{CANARY_DOMAIN}%ff.{whitelistedHost}",
    f"http://{whitelistedHost}%25253F@{CANARY_DOMAIN}",
    f"http://{whitelistedHost}%253F@{CANARY_DOMAIN}",
    f"http://{whitelistedHost}%3F@{CANARY_DOMAIN}",
    f"http://{whitelistedHost}@{CANARY_DOMAIN}",
    f"http://foo@{CANARY_DOMAIN}:80@{whitelistedHost}",
    f"http://foo@{CANARY_DOMAIN}%20@{whitelistedHost}",
    f"http://foo@{CANARY_DOMAIN}%09@{whitelistedHost}"
    ]
    return generated

def prepare_url_with_regex(url):

    replacedURL = regex.sub(regexMultipleParams, FUZZ_PLACE_HOLDER, url, flags=regex.IGNORECASE)
    if replacedURL == url: #If no match with multiparam regex
        replacedURL = regex.sub(regexSingleParam, FUZZ_PLACE_HOLDER, url, flags=regex.IGNORECASE)
        matchedElem = regex.search(regexSingleParam, url, regex.IGNORECASE)
    else:
        matchedElem = regex.search(regexMultipleParams, url, regex.IGNORECASE)

    if matchedElem:
        matchedElem = matchedElem.group()

    return replacedURL, matchedElem

def fuzz_open_redirect(url, payloadsList = payloads):

    replacedURL, matchedElem = prepare_url_with_regex(url)

    if not matchedElem: #No relevant parameter matching
        return

    if args.smart:
        host = smart_extract_host(url, matchedElem)
        payloadsList += generate_payloads(host)


    if args.verbose:
        if not args.threads:
            print(f"+ + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + +")
        print(f"Starting fuzzing {replacedURL}")

    for payload in payloadsList:
        if detected_vuln_with_payload(replacedURL, payload):
            print(f"Open Redirect detected in {replacedURL} with payload {payload}.")
            with LOCK:
                output.write(f"Open Redirect detected in {replacedURL} with payload {payload}\n")
            return
    if args.verbose:
        print(f"\nNothing detected for {replacedURL}\n")

def detected_vuln_with_payload(url, payload):
    fuzzedUrl = url.replace(FUZZ_PLACE_HOLDER, payload)

    if args.verbose:
        if not args.threads:
            print(f"Testing payload: {payload}                                                          ", end="\r")
    response = requests.get(fuzzedUrl, timeout=TIMEOUT_DELAY)
    return (CANARY_TEXT in response.text)


def sequential_url_scan(urlList):

    for url in urlList:
        try:
            fuzz_open_redirect(url)
        except requests.exceptions.Timeout:
            exception_verbose_message("timeout")
        except requests.exceptions.TooManyRedirects:
            exception_verbose_message("redirects")
        except requests.exceptions.RequestException:
            exception_verbose_message("others")

def main():
    if args.url:
        try:
            fuzz_open_redirect(args.url)
        except:
            print("\nInvalid URL")
    elif args.file:

        if not args.threads or args.threads == 1:
            sequential_url_scan(allURLs)

        else:
            workingThreads = []
            split = splitURLS(args.threads)
            for subList in split:
                t = threading.Thread(target=sequential_url_scan, args=[subList])
                t.start()
                workingThreads.append(t)
            for thread in workingThreads:
                thread.join()
    output.close()


if __name__ == '__main__':
    main()
