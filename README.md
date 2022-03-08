### Summary

**autoRedirect** is your best ally for identifying open redirections at scale. Different from other Open Redirects scanners, **autoRedirect** comes with the three following original features :

- **Smart fuzzing on relevant open redirect GET parameters**
    
    When fuzzing, **autoRedirect** only focuses on the common parameters related to open redirects (`?redirect_to=`, `?goto=`, ..) and doesn’t interfere with everything else. This ensures that the original URL is still correctly understood by the tested web-application, something that might doesn’t happen with a tool blindly spraying every query parameters.
    
- **Context-based dynamic payloads generation**
    
    For the given URL : `[https://host.com/?redirect_to=https://authorizedhost.com](https://host.com/?fileURL=https://whitelistedhost.comn)`, with *smart mode* activated, **autoRedirect** would recognize *authorizedhost.com* as the potentially white-listed host for the web-application, and generate payloads dynamically based on that, attempting to bypass the white-list validation. 
    It would result to interesting payloads such as : `http://authorizedhost.attacker.com`, `http://authorizedhost%252F@attacker.com`, etc.
    
- **Precise and certain vulnerability detection**
    
    Unlike other tools, **autoRedirect** doesn’t output imprecise basic heuristics but is able to confidently detect, with false-positive rate close to zero, open redirections. In fact, instead of simply outputting the 302 redirect’s URL after injecting payload, **autoRedirect** would follow all redirects, read content of the very last page that doesn’t lead to a new redirect, and return a result if and only if a *CANARY* is present in the text. Technically, *CANARY*’s content is readable from the following URL [`canaryredirect.fr`](http://canaryredirect.fr/), where *canaryredirect.fr* has been exclusively set-up for the tool, and is included in every payloads. The tool managing to correctly read the *CANARY*, would be, thus, the obvious indicator that an open redirection occurred from target’s URL to `canaryredirect.fr`*.*
    

---

### Usage

```bash
python3 autoredirect.py -h
```

This displays help for the tool.

```
usage: autoredirect.py [-h] [--file FILE] [--url URL] [--threads THREADS]
                       [--verbose] [--smart] [--oneshot] [--output]

options:
  -h, --help            show this help message and exit
  --file FILE, -f FILE  file of all URLs to be tested against Open Redirect
  --url URL, -u URL     url to be tested against Open Redirect
  --threads THREADS, -n THREADS
                        number of threads for the tool
  --verbose, -v         activate verbose mode for the tool
  --smart, -s           activate context-based payload generation for each
                        tested URL
  --oneshot, -t         fuzz with only one basic payload - to be activated in
                        case of time constraints
  --output, -o          output file path
```

Single URL target: 

```bash
python3 autoredirect.py -u https://www.host.com/?param1=X&param2=Y&param2=Z
```

Multiple URLs target with smart mode: 

```bash
python3 autoredirect.py -f urls.txt -s
```

---

### Example output

**autoRedirect** launched against a Swisscom’s open redirect vulnerable URL (with verbose mode activated): 

```
Starting fuzzing https://i-solutions.swisscom.com/sap/public/bc/icf/logoff?redirecturl=???
Open Redirect detected in https://i-solutions.swisscom.com/sap/public/bc/icf/logoff?redirecturl=??? with payload http://canaryredirect.fr.
```

---

### Installation

1 - Clone 

```bash
git clone https://github.com/Th0h0/autoredirect.git
```

2  - Install requirements

```bash
cd autoredirect 
pip install -r requirements.txt
```

---

### License

**autoredirect** is distributed under [MIT License](https://github.com/Th0h0/autoredirect/blob/master/LICENSE.md).
