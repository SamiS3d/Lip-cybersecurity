from utils.colors import Colors

class XSSScanner:
    def __init__(self, requester, reporter):
        self.req = requester
        self.reporter = reporter
        self.payload = "<script>alert('CoreInspect_XSS')</script>"

    def scan_url(self, url):
        if "?" not in url:
            return False
            
        test_url = url + self.payload
        response = self.req.get(test_url)
        
        if response and self.payload in response.text:
            print(f"{Colors.VULN} XSS (Cross-Site Scripting) found at URL: {test_url}")
            self.reporter.add_vulnerability("Reflected XSS (GET)", test_url, f"Payload: {self.payload}")
            return True
        return False

    def scan_form(self, form):
        target_url = form['action']
        method = form['method']
        
        data = {}
        for input_tag in form['inputs']:
            input_name = input_tag['name']
            data[input_name] = self.payload
        
        if method == 'post':
            response = self.req.post(target_url, data=data)
        else:
            response = self.req.get(target_url, params=data)
            
        if response and self.payload in response.text:
            print(f"{Colors.VULN} XSS found in Form at: {form['url']}")
            self.reporter.add_vulnerability("Reflected XSS (Form)", form['url'], f"Payload: {self.payload} | Data: {data}")
            return True
        return False