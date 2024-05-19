from flask import Flask, redirect,url_for,render_template,request,jsonify
from pymongo import MongoClient
from bson.objectid import ObjectId
import requests
import shodan 
import json
import time
from zapv2 import ZAPv2
from threading import Thread

SHODAN_API_KEY = "sP0jZedwmwja7nRupTLHFjsRW17fOSH0"
api = shodan.Shodan(SHODAN_API_KEY)


app=Flask(__name__)
client = MongoClient('mongodb://localhost:27017/') 
db = client['demo'] 

collection=db['data']
collection1=db['url']
collection2=db['image']





@app.route('/')
def home():
    return render_template("index.html")
    
@app.route('/registration')
def registration():
    return render_template('registration.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/services')
def services():
    return render_template('service.html')


'''------------------------------------------------------------------------------------------'''
@app.route('/shodan1',methods=['POST','GET'])
def shodan1():
    if request.method=='GET':
         return render_template("shodan.html")
    if request.method=='POST':
        if(request.form['url']==''):
            return "<html><body><h1>Invalid port or network</h1></body></html>"
        else:
            num=request.form['url']
            #inserted_id = collection.insert_one({'number': num}).inserted_id
           #document = collection.find_one({'_id': inserted_id})
            #enter = input("Enter IP address: ")
            url = f'https://api.shodan.io/shodan/host/{num}?key={SHODAN_API_KEY}'
            response = requests.get(url)

            if response.status_code == 200:
                js = response.json()
                print(type(js))
                js1=json.dumps(js, indent=4)
                #print("\nParsed Information:")
                js2={}
                js2['IP'] = js.get('ip_str', 'N/A')
                js2['Organization'] = js.get('org', 'N/A')
                js2['Operating System'] = js.get('os', 'N/A')
                js2['ISP'] = js.get('isp', 'N/A')
                js2['Last Update'] = js.get('last_update', 'N/A')
                # print(f"IP: {js.get('ip_str', 'N/A')}")
                # print(f"Organization: {js.get('org', 'N/A')}")
                # print(f"Operating System: {js.get('os', 'N/A')}")
                # print(f"ISP: {js.get('isp', 'N/A')}")
                # print(f"Last Update: {js.get('last_update', 'N/A')}")




           
        
           
          
           
            return render_template("shodan.html",number=js2)
        



'''--------------------------------------------------------------------------------------------'''
@app.route('/cve',methods=['POST','GET'])
def cve():
    if request.method=='GET':
         return render_template("cve.html")
    if request.method=='POST':
        if(request.form['url']==''):
            return "<html><body><h1>Invalid url</h1></body></html>"
        else:
            num=request.form['url']
            #inserted_id1=collection1.insert_one({'number':num}).inserted_id
            #document1=collection1.find_one({'_id':inserted_id1})
            #collection1.insert_one({'number':num})
            Url = 'https://vulners.com/api/v3/search/lucene/'
            software_list = ["Apache", "Nginx", "WordPress", "PHP", "MySQL", "Drupal"]  # Add more software names as needed

            api_key = "8D0YU2TBX6J7CGWXD8TC12ZB8T3JCGDGWW0440RNNEG7SQ0G3P9ZJVZIW5L1AQ4O"  # Replace with your actual API key

            for software in software_list:
                        data = {
                                  "query": software,
                                "apiKey": api_key
                               }

 
        # Make the POST request to the Vulners API
                        response = requests.post(Url, json=data)
                        response.raise_for_status()  # Raises an HTTPError for bad responses

        # Parse the JSON response
                        response_data= response.json()
            
            

        return render_template("cvescan_example.html",response_data=response_data)
        
'''------------------------------------------------------------------------------------------------'''
@app.route('/imagescan',methods=['POST','GET'])
def imagescan():
    if request.method=='GET':
      return render_template("imagescan.html")
    if request.method=='POST':
        if(request.form['url']==''):
            return "<html><body><h1>Iupload an image</h1></body></html>"
        else:
            '''num=request.form['url']
            inserted_id2=collection2.insert_one({'number':num}).inserted_id
            document2=collection2.find_one({'_id':inserted_id2})
            collection2.insert_one({'number':num})'''
            Url = "https://check-ssl.p.rapidapi.com/sslcheck"

            querystring = {"domain":"amazon.com"}

            headers = {
                        "X-RapidAPI-Key": "4c38c122fcmsh82e6abd326c09efp1b9f96jsne2361a2bb7c7",
                          "X-RapidAPI-Host": "check-ssl.p.rapidapi.com"
            }

            response = requests.get(Url, headers=headers, params=querystring)

# Check if the request was successful (status code 200)
            if response.status_code == 200:
    # Extract the required fields
                   data = response.json()
                   required_fields1= {
        
                                 "canBeSelfSigned": data["canBeSelfSigned"],
                                  "isWildCard": data["isWildCard"],
                                "isExpired": data["isExpired"],
                                "message": data["message"],
                                "expiry": data["expiry"],
                                "daysLeft": data["daysLeft"],
                                "lifespanInDays": data["lifespanInDays"],
                                "issuer": data["issuer"]
                    }
            return render_template("ssl_example.html",required_fields=required_fields1)

'''------------------------------------------------------------------------------------------------------------'''




@app.route('/zapy')


def zapy():
    # Define the ZAP object
    apiKey = 'sdb8qi4npgtdbob8o0n13bai0a'
    zap = ZAPv2(apikey=apiKey)

    target = 'https://spice-3-0.onrender.com/'
    
    # Spidering target
    spider_scan_id = zap.spider.scan(target)
    spider_results = wait_for_completion(zap.spider.status, spider_scan_id, 'Spider', zap)
    
    # Start active scan in a separate thread
    active_scan_thread = Thread(target=active_scan, args=(zap, target,))
    active_scan_thread.start()

    # Wait for the active scan thread to finish
    active_scan_thread.join()
    
    # Print vulnerabilities found by the scanning
    hosts = zap.core.hosts
    alerts = zap.core.alerts(baseurl=target)

    return render_template('zapy.html', spider_results=spider_results, hosts=hosts, alerts=alerts)

def wait_for_completion(status_func, scan_id, task_name, zap, poll_interval=1):
    while True:
        status = status_func(scan_id)
        print(f'{task_name} progress %: {status}')
        if status == '100':
            break
        time.sleep(poll_interval)
    print(f'{task_name} has completed!')
    # Parse and print the URLs the spider has crawled
    return zap.spider.results(scan_id)

def active_scan(zap, target):
    print('Active Scanning target {}'.format(target))
    scan_id = zap.ascan.scan(target)
    wait_for_completion(zap.ascan.status, scan_id, 'Active Scan', zap, poll_interval=2)

'''---------------------------------------------------------------------------------------------------------------'''
if(__name__)=='__main__':
    app.run(debug=True)