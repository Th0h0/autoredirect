import regex
import argparse
import requests

CANARY_TEXT = 'CANARY049'
CANARY_DOMAIN = 'canaryredirect.fr'
FUZZ_PLACE_HOLDER = 'FUZZ-HERE'

parser = argparse.ArgumentParser()
parser.add_argument("--file", "-f", type=str, required=False, help= 'file of all URLs to be tested against Open Redirect')
parser.add_argument("--url", "-u", type=str, required=False, help= 'url to be tested against Open Redirect.')
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

regexMultipleParams = '(?<=(Url|URL|Open|callback|checkout|continue|data|dest|destination|dir|domain|feed|file|file_name|folder|forward|go|goto|host|html|load_file|login\?to|logout|navigation|next|next_page|out|page|path|port|redir|redirect|redirect_to|uri|URI|Uri|reference|return|returnTo|return_path|return_to|show|site|target|to|url|val|validate|view|window)=)(.*)(?=&)'

regexSingleParam = '(?<=(Url|URL|Open|callback|checkout|continue|data|dest|destination|dir|domain|feed|file|file_name|folder|forward|go|goto|host|html|load_file|login\?to|logout|navigation|next|next_page|out|page|path|port|redir|redirect|redirect_to|uri|URI|Uri|reference|return|returnTo|return_path|return_to|show|site|target|to|url|val|validate|view|window)=)(.*)'

if args.output:
    output = open(args.output, "w")
else:
    output = open("open-redirect-output.txt", "w")


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

def fuzz_open_redirect(url, payloadsList = payloads):
    matching = regex.search(regexMultipleParams, url, regex.IGNORECASE)
    matchedElem = matching if matching else regex.search(regexSingleParam, url, regex.IGNORECASE)
    if not matchedElem:
        return
    matchedElem = matchedElem.group()

    if args.smart:
        host = smart_extract_host(url , matchedElem)
        payloadsList += generate_payloads(host)

    url = url.replace(matchedElem, FUZZ_PLACE_HOLDER)

    if args.verbose:
        print(f" + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + +")
        print(f"Starting fuzzing {url}")

    for payload in payloadsList:
        if detected_vuln_with_payload(url, payload):
            print(f"Open Redirect detected in {url} with payload {payload}.")
            output.write(f"Open Redirect detected in {url} with payload {payload}\n")
            return
    if args.verbose:
        print("\nNothing detected for the given URL.\n")

def detected_vuln_with_payload(url, payload):
    fuzzedUrl = url.replace(FUZZ_PLACE_HOLDER, payload)

    if args.verbose:
        print(f"Testing payload: {payload}                                                          ", end="\r")
    response = requests.get(fuzzedUrl)
    return (CANARY_TEXT in response.text)

def main():
    if args.url:
        try:
            fuzz_open_redirect(args.url)
        except:
            print("\nInvalid URL")
    elif args.file:

        targetURLS = open(args.file, "r")

        for url in targetURLS:
            try:
                fuzz_open_redirect(url)
            except:
                continue
        targetURLS.close()
main()
