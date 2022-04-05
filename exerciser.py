# Libraries 
from posixpath import split
import requests
import json
import os
import enum
import sys
import argparse
from datetime import datetime
from selenium import webdriver
from time import sleep
from selenium.webdriver.common.by import By
from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.common.proxy import Proxy, ProxyType
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.keys import Keys
options = Options()

# Statuses
class Status(enum.Enum):
   SUCCESS = 0
   FAIL = 1
   UNSTABLE = 2
   OTHER = -1

# Global variables  

# Steve EOP NIX TS
#CONTRAST_ORG=""
#BASEURL="http://ts.contrast.pw:8080/Contrast/api/ng/%s" % CONTRAST_ORG
#CONTRAST_AUTH=""
#CONTRAST_API_KEY=""

# Steve SaaS Apptwo TS
CONTRAST_ORG=""
BASEURL="https://apptwo.contrastsecurity.com/Contrast/api/ng/%s" % CONTRAST_ORG
CONTRAST_AUTH=""
CONTRAST_API_KEY=""

# Global Vars
APP_URL=""
APP_LOGIN_URL=""

today_date = datetime.now()
date_time = today_date.strftime('%Y-%m-%d %H:%M')

# Initialize output
output = {
    'logs' : []
}

# Append data 
def log(entry):
    '''
    Append new log entries
    '''
    output['logs'].append(entry)

    with open("output.json", "w") as outfile:
        json.dump(output, outfile, indent=4)

# Usage and help
def get_usage():
    """Returns the usage information for this tool.
    """
    return'''

%s 

Explanation:
    This script attempts to exercise routes Discovered but not Exercised using the Contrast API, Python Requests, and the Firefox Web Driver.

Optional arguments: 
    -a        --app           List all app names
    -l        --login         Uses Firefox Web Driver to login
    -i        --interactive   Takes Firefox Web Driver out of headless mode
    -h        --help          Print this help message
    -n        --name          Specify app name; pulls app_id from API and tells Web Driver how to login  
    -t        --terminate     Terminate WebDriver (kills all Firefox processes)
    -v        --version       Version of this program

Examples:
    python3 exercise.py --interactive
'''% sys.argv[0]

# Parse command line arguments
def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='This script attempts to exercise routes not Exercised using the Contrast API, Python Requests, and the Firefox Web Driver.', add_help=False, usage=get_usage())
    parser.add_argument('-a', '--app', help='List all app names.', action='store_true')
    parser.add_argument('-l', '--login', help='Use Firefox Web Driver to login.', action='store_true') 
    parser.add_argument('-i', '--interactive', help='Use Interactive mode so that you can use the browser to interact with the pages.', action='store_true') 
    parser.add_argument('-h', '--help', help='This help file.')
    parser.add_argument('-n', '--name', type=str, help='Specify app name to get app_id, enable logins, etc.')
    parser.add_argument('-t', '--terminate', help='Kill all FireFox processes.', action="store_true")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 3.0', help='The program version number.')
    return parser

# Call the Requests library for specific URLs in other functions, check for and log errors
def get_url(url, headers):
    '''
    Function to enumerate data from a URL or API endpoint.
    '''

    response = requests.get(url, headers=headers, allow_redirects=True, timeout=5)

    if response.status_code == 200:
        result=json.loads(response.text)
    
    elif response.status_code > 399:
        print(f"We were unable to pull info from this endpoint.\n")
        log (f"{date_time} URL: {url} HEADERS: {headers} HTTP error: {response.status_code}")
        log (response.text)
        sys.exit()

    else:
        raise Exception("Error while getting data.", response.status_code, response.text) 

    return result     

def login(APP_LOGIN_URL, id_element, password_element, id, password):
    '''
    Function used to log into a webapp with FireFox Web Driver
    '''
    
    print(f"\nLogging into %s" % (APP_LOGIN_URL))  
    driver.get("%s" % (APP_LOGIN_URL))
    print(f"\nEntering Username")
    driver.find_element(By.ID, id_element).send_keys(id)
    print(f"Entering Password")
    driver.find_element(By.ID, password_element).send_keys(password) 
    print(f"Submitting Username and Password")

    if button_login == "yes":
        driver.find_element(By.CSS_SELECTOR, ".btn").click()
    
    if button_login == "no":
        driver.find_element(By.ID, password_element).send_keys(Keys.ENTER)

    print(f"\nStarting to attempt to exercise routes ...")

    return

def crawl_discovered(verb, obs_url, url):
    '''
    Function used to exercise routes enumerated from the Contrast API using the Requests library
    '''
    if args.interactive and verb == "get":
        # need to set proxy for Firefox
        driver.get('%s%s' % (APP_URL, obs_url))

    if args.interactive and verb == "post":
        headers = {'Accept':"application/json"}
        requests.post(url, headers) 

    if args.interactive and verb == "put":
        headers = {'Accept':"application/json"}
        requests.put(url, headers) 

    if not args.interactive:
        if (verb == "get"):
            sep = "/"
            file = obs_url.rsplit(sep, 1)[1]
            driver.get('%s%s' % (APP_URL, obs_url))
            if os.path.exists("~/Downloads/%s" % (file)):
                print("Found folder: %s" % (file))
            if os.path.isfile("~/Downloads/%s" % (file)):
                print("Found file: %s" % (file))   
            driver.refresh()

    if (verb == "post"):
            headers = {'Accept':"application/json"}
            data = "test_data"
            requests.post(url, headers, data)

    if (verb == "put"):
        headers = {'Accept':"application/json"}
        requests.put(url, headers)

    return 

def list_apps():
    '''
    Function to list application name choices.
    '''   

    print(f"Available apps:\n")
    print(f"eShopOnWeb")
    print(f"eShopOnWeb-Pipeline")
    print(f"RailsGoat") 
    print(f"WebGoat-POM")
    print(f"WebGoat-7.1")
    print(f"WebGoat-8.1")
    print(f"WebGoat_Latest_Pipeline")
    print(f"Vulpy") 
    print(f"VAmPy") 
    print(f"NodeGoat") 
    print(f"Ticketbook") 
    print(f"WebGoat.net") 

    return

def identify_app(name):
    '''
    Function that identifies an application in Contrast using the name or part of the name.
    '''

    url = '%s/applications/name?filterText=%s' % (BASEURL, name)
    headers = {"Accept": "application/json", "API-Key": CONTRAST_API_KEY, "Authorization": CONTRAST_AUTH}
    results=get_url(url, headers)
        
    if results['success']:
        filtered_app = [app for app in results["applications"] if app["name"] == name]
        if(len(filtered_app) == 1):
            app = filtered_app[0] 
        else:
            raise Exception("No application found for ", name)
    else:
        raise Exception("Error while getting application name", results)
    return app

def exercise_routes(app_id):
    '''
    Function used to obtain routes from Contrast API and crawl them with the Requests library
    '''

    url = '%s/applications/%s/route' % (BASEURL, app_id)
    headers = {"Accept": "application/json", "API-Key": CONTRAST_API_KEY, "Authorization": CONTRAST_AUTH}
    results=get_url(url, headers)

    all_routes = results['routes']

    #print(json.dumps(results, indent=4))

    for route in all_routes:
        url = '%s/applications/%s/route/%s/observations' % (BASEURL, app_id, route['route_hash'])
        results=get_url(url, headers)
            
        all_observations = results['observations']
        signature = route['signature']
        exercised = route['exercised']
        verb = results['observations'][0]['verb'].lower()
        obs_url = results['observations'][0]['url']
        
        if all_observations:
            if verb == "":
                verb = "get" 

            url = APP_URL+obs_url

            if name == ("RailsGoat" or "railsgoat"):
                sep = "("
                first_url = url.rsplit(sep, 1)[0]
                #last_param = url.rsplit(sep, 1)[1]

                #print("First url: " + first_url)
                #print("Last part of url: " + last_param)

                #if last_param == id:
                    #id = "steve.smith@contrastsecurity.com"
                    #last_param = id

                url = first_url

            if exercised == None or "DISCOVERED":
                          
                print(f"Attempt to exercise %s request %s (%s)" % (verb, url, exercised))			
                log("Attempt to exercise %s request %s (%s)" % (verb, url, exercised))
                crawl_discovered(verb, obs_url, url)
                        
            else:
                print("Already exercised %s %s #   <!-- TESTED %s -->" % (verb, url, signature))
                log("Already exercised %s %s #   <!-- TESTED %s -->" % (verb, url, signature)) 
        
    return

def main():
    '''
    Main function
    '''

    return

if __name__ == '__main__':
    
    try:
        parser = init_argparse()
        args = parser.parse_args()

        if args.name:
            name = args.name
            print("You specified application: %s" % (args.name))
            app = identify_app(args.name) 
            if(not app):
                print("ERROR - No application found for given application name %s." % (args.name))
                exit(Status.OTHER.value)
            global app_id, app_name
            app_id = app["app_id"]
            app_name = app["name"]
 
        if ("eShopOnWeb" or "eshoponweb") in args.name:
            APP_URL = "http://eshoponweb.contrast.pw:5106"
            APP_LOGIN_URL = "http://eshoponweb.contrast.pw:5106/Identity/Account/Login"
            log_in = "yes"
            button_login = "yes"
            id_element = "Input_Email"
            password_element = "Input_Password"
            id = ""
            password = "" 

        if ("RailsGoat" or "railsgoat") in args.name:
            APP_URL = "http://railsgoat.contrast.pw:3000"
            APP_LOGIN_URL = "http://railsgoat.contrast.pw:3000/login?"
            log_in = "yes"
            button_login = "no"
            id_element = "email"
            password_element = "password"
            id = ""
            password = ""   

        if ("WebGoat" or "webgoat") in args.name:
            APP_URL = "http://webgoat.contrast.pw:8080/WebGoat"
            APP_LOGIN_URL = "http://webgoat.contrast.pw:8080/WebGoat/login" 
            log_in = "yes"
            button_login = "yes"
            id_element = "exampleInputEmail1"
            password_element = "exampleInputPassword1"
            id = ""
            password = ""      

        if ("Vulpy" or "vulpy") in args.name:
            APP_URL = "http://vulpy.contrast.pw:5000"
            APP_LOGIN_URL = "http://vulpy.contrast.pw:5000"
            log_in = "yes"

        if ("VAmPy" or "vampy") in args.name:
            APP_URL = "http://vampy.contrast.pw"
            APP_LOGIN_URL = "http://vampy.contrast.pw"
            log_in = "yes"

        if ("NodeGoat" or "nodegoat") in args.name:
            APP_URL = "http://nodegoat.contrast.pw:4000"
            APP_LOGIN_URL = "http://nodegoat.contrast.pw:4000"
            log_in = "yes"
            button_login = "no"
            id_element = "username"
            password_element = "password"
            id = ""
            #id = ""
            password = ""
            #password = ""   

        if ("WebGoat.net" or "webgoat.net" or "webgoatnet") in args.name:
            APP_URL = "http://webgoatnet.contrast.pw"    
            APP_LOGIN_URL = "http://webgoatnet.contrast.pw" 
            log_in = "yes"
            button_login = "yes"

        if ("Ticketbook" or "ticketbook") in args.name:
            APP_URL = "http://ticketbook.contrast.pw:8080/ticketbook"
            APP_LOGIN_URL = "http://ticketbook.contrast.pw:8080/ticketbook"
            log_in = "yes"

        if args.interactive:
            print(f"\nEnabling Interactive mode.\n")
            input("Make sure you're ready. Press Enter to continue...")
            options.headless = False
            driver = webdriver.Firefox(options=options)
            driver.implicitly_wait(3)

        if not args.interactive and not args.app:
            print(f"Running in Headless mode.")
            options.headless = True
            driver = webdriver.Firefox(options=options)
            driver.implicitly_wait(3)

        if args.app:
            list_apps()
            exit(Status.OTHER.value)

        if args.login:
            if log_in == "yes":
                login(APP_LOGIN_URL, id_element, password_element, id, password)
            if log_in == "no":
                exercise_routes(app_id)

        exercise_routes(app_id)
        driver.close()
        driver.quit()

        if args.terminate:
            os.system("killall -9 firefox-bin")
 
    except argparse.ArgumentError as args:
        parser.print_help()
        exit(Status.OTHER.value)

    except Exception as e: 
        log(e)
        exit(Status.OTHER.value)        

exit(Status.SUCCESS.value) 
