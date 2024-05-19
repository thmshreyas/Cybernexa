import time
from zapv2 import ZAPv2
from threading import Thread

# The URL of the application to be tested
target = 'https://spice-3-0.onrender.com/'
# Change to match the API key set in ZAP, or use None if the API key is disabled
apiKey = 'sdb8qi4npgtdbob8o0n13bai0a'

# By default ZAP API client will connect to port 8080
zap = ZAPv2(apikey=apiKey)
# Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
# zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

print('Spidering target {}'.format(target))
# The scan returns a scan id to support concurrent scanning
spider_scan_id = zap.spider.scan(target)

def wait_for_completion(status_func, scan_id, task_name, poll_interval=1):
    while True:
        status = status_func(scan_id)
        print(f'{task_name} progress %: {status}')
        if status == '100':
            break
        time.sleep(poll_interval)
    print(f'{task_name} has completed!')

# Wait for the spidering to complete
wait_for_completion(zap.spider.status, spider_scan_id, 'Spider', poll_interval=0.5)

# Parse and print the URLs the spider has crawled
spider_results = zap.spider.results(spider_scan_id)
print('Spider Results:')
for result in spider_results:
    print('- URL:', result)

def active_scan(target):
    print('Active Scanning target {}'.format(target))
    scan_id = zap.ascan.scan(target)
    wait_for_completion(zap.ascan.status, scan_id, 'Active Scan', poll_interval=2)

# Start active scan in a separate thread
active_scan_thread = Thread(target=active_scan, args=(target,))
active_scan_thread.start()

# Wait for the active scan thread to finish
active_scan_thread.join()

# Print vulnerabilities found by the scanning
hosts = zap.core.hosts
print('Hosts: {}'.format(', '.join(hosts)))

alerts = zap.core.alerts(baseurl=target)
print('Alerts:')
for alert in alerts:
    print('- Alert:', alert.get('alert', 'N/A'))
    print('  - URL:', alert.get('url', 'N/A'))
    print('  - Risk Level:', alert.get('risk', 'N/A'))
    print('  - Description:', alert.get('description', 'N/A'))
    print('  - Solution:', alert.get('solution', 'N/A'))
    print('  - Other:', alert.get('otherinfo', 'N/A'))
    print('  - Reference:', alert.get('reference', 'N/A'))