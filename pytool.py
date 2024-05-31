import requests
import re
import json
import argparse
import pandas as pd
from prettytable import PrettyTable, ALL
from termcolor import colored
import os
import dns.resolver
from colorama import Fore, Style
from bs4 import BeautifulSoup

# Verifica se il file esiste, altrimenti lo crea
with open('dataabuse.json', 'w') as file:
    if os.path.exists('dataabuse.json'):
        file.write('')  # Sovrascrivi il file esistente
    else:
        file.write('[]')
with open('dataproxy.json', 'w') as file:
    if os.path.exists('dataproxy.json'):
        file.write('')  # Sovrascrivi il file esistente
    else:
        file.write('[]')
with open('datavt.json', 'w') as file:
    if os.path.exists('datavt.json'):
        file.write('')  # Sovrascrivi il file esistente
    else:
        file.write('[]')  # Crea un nuovo file e scrivi un oggetto JSON vuoto
with open('dfall.json', 'w') as file:
    if os.path.exists('dfall.json'):
        file.write('')  # Sovrascrivi il file esistente
    else:
        file.write('[]')
with open('datacr.json', 'w') as file:
    if os.path.exists('datacr.json'):
        file.write('')  # Sovrascrivi il file esistente
    else:
        file.write('[]')
def boolean_to_uppercase(data):
    if isinstance(data, bool):
        return str(data).capitalize()
    elif data is None:
        return "Null"
    elif isinstance(data, dict):
        return {key: boolean_to_uppercase(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [boolean_to_uppercase(item) for item in data]
    else:
        return data

def write_json_with_uppercase(data, file):
    uppercase_data = boolean_to_uppercase(data)
    json.dump(uppercase_data, file, ensure_ascii=False)
    
def convert_to_uppercase(data):
    # Funzione ricorsiva per convertire le chiavi dei dizionari in maiuscolo
    if isinstance(data, dict):
        return {key.upper(): convert_to_uppercase(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [convert_to_uppercase(item) for item in data]
    else:
        return data
def query_abuseipdb(api_key, query):
    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={query}&maxAgeInDays=90'
    headers = {'Key': api_key, 'Accept': 'application/json'}
    response = requests.get(url, headers=headers)
    try: 
        data = response.json()
        
        print("Got AbuseIPDB Data:")
        #print(data)  # Stampa i dati restituiti da AbuseIPDB
        
        with open('dataabuse.json', 'a') as f:  # Apri il file in modalità di append
            write_json_with_uppercase(data, f)
            f.write('\n')
        return data
    except json.decoder.JSONDecodeError:
        print(f"No data received from Abuseipdb for: {query}")
        return {}
    except IOError as e:
        print(f"Error writing to dataabuse.json: {e}")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
def query_proxycheck(api_key, query):
    url = f'https://proxycheck.io/v2/{query}?key={api_key}&vpn=1&asn=1&asnname=1&inf=1&risk=1&tag=1'
    response = requests.get(url)
    try:
        response.raise_for_status()
        
        # Decodifica la risposta
        response_text = response.content.decode('utf-8')
        
        # Rimuovi i caratteri non ASCII
        response_text = re.sub(r'[^\x00-\x7F]+', '', response_text)
        
        data = json.loads(response_text)
        
        print("Got ProxyCheck Data:")
        #print(data)  # Stampa i dati restituiti da ProxyCheck
        
        with open('dataproxy.json', 'a') as f:
            write_json_with_uppercase(data, f)
            f.write('\n') 
        return data
    except json.decoder.JSONDecodeError:
        print(f"No data received from AbuseIpDb for: {query}")
        return {}
    except IOError as e:
        print(f"Error writing to dataabuse.json: {e}")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
def query_virustotald(api_key, query):
    url = f"https://www.virustotal.com/api/v3/domains/{query}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)

    try:
    
        data = response.json()
        
        print("Got VirusTotal Data:")
        #print(data)  # Stampa i dati restituiti da ProxyCheck
        
        with open('datavt.json', 'a') as f:
            write_json_with_uppercase(data, f)
            f.write('\n') 
        return data
        
    except json.decoder.JSONDecodeError:
        print(f"No data received from Proxycheck for: {query}")
        return {}
    except IOError as e:
        print(f"Error writing to dataproxy.json: {e}")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
def query_virustotalip(api_key, query):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{query}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    #print(response.text)

    try:
    
        data = response.json()
        
        print("Got VirusTotal Data:")
        #print(data)  # Stampa i dati restituiti da ProxyCheck
        
        with open('datavt.json', 'a') as f:
            write_json_with_uppercase(data, f)
            f.write('\n') 
        return data
        
    except json.decoder.JSONDecodeError:
        print(f"No data received from VirusTotal for: {query}")
        return {}
    except IOError as e:
        print(f"Error writing to datavt.json: {e}")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
def query_criminalip(api_key, query):
    url = f"https://api.criminalip.io/v1/asset/ip/report/summary?ip={query}"
    header =  {"x-api-key": api_key}
    response = requests.get(url, headers=header)
    #print(response.text)
    try:
    
        data = response.json()
        
        print("Got CriminalIp Data:")
        #print(data)  # Stampa i dati restituiti da ProxyCheck
        
        with open('datacr.json', 'a') as f:
            write_json_with_uppercase(data, f)
            f.write('\n') 
        return data
        
    except json.decoder.JSONDecodeError:
        print(f"No data received from CriminalIp for: {query}")
        return {}
    except IOError as e:
        print(f"Error writing to datacr.json: {e}")
        return {}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {}
    
def get_domain_ips(domain):
    try:
        ips = dns.resolver.resolve(domain, 'A')
        return [ip.address for ip in ips]
    except dns.resolver.NoAnswer:
        return []
def clean_query_result(query_result):
    if "status" in query_result:
        keys = list(query_result.keys())
        return query_result[keys[1]]
    elif "data" in query_result:
        return query_result["data"]
    else:
        return query_result
def colore_stile(val):
    # Cambia colore solo per i valori 'Malicious'
    if val == 'Malicious':
        return f'{Fore.RED}{val}{Style.RESET_ALL}'  # Rosso
    return val
def check_anonymity(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    h2_tags = soup.find_all('h2', class_='mb-3 text-left')
    print("Got Spur Data:")
    for h2_tag in h2_tags:
        if 'Not Anonymous' in h2_tag.get_text():
            return "Not Anonymous"
        else:
            return h2_tag.find('span').get_text().strip()

def get_data_from_spur(query):
    url = f"https://spur.us/context/{query}"
    response = requests.get(url)
    if response.status_code == 200:
        html_content = response.content
        data = check_anonymity(html_content)
        return data
    else:
        print("Errore nella richiesta:", response.status_code)
        return None
    
def get_subnet(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    p_tags = soup.find_all('p')
    
    for p_tag in p_tags:
        if 'No IP addresses from this subnet have been reported.' in p_tag.get_text():
            return "No IP addresses from this subnet have been reported."
        else:
            return p_tag.get_text().strip()

def get_subnet_reports(query, queryrange):
    queryrange= str(queryrange[0])
    queryrange = queryrange.replace('/', '')
    queryrange = int(queryrange)
    if queryrange < 24:
        queryrange = 24
    queryrange= str(queryrange)
    url = f"https://www.abuseipdb.com/check-block/{query}/{queryrange}"
    user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    headers = {'User-Agent': user_agent}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        html_content = response.content
        data = get_subnet(html_content)
        return data
    else:
        #print("Errore nella richiesta:", response.status_code)
        return url

    
def main():
    parser = argparse.ArgumentParser(description='Query multiple services for IP/domain information.')
    parser.add_argument('queries', metavar='QUERY', nargs='+', help='IP address or domain to query')
    args = parser.parse_args()

    # Insert here your API keys
    virustotal_api_key = ''
    abuseipdb_api_key = ''
    proxycheck_api_key = ''
    criminalip_api_key = ''

    results = []

    for query in args.queries:
        # Controllo se l'input è un indirizzo IP o un nome di dominio
        ip_pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
        domain_pattern = r"^(?!:\/\/)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}(\/\S*)?$"
        
        if re.match(ip_pattern, query):  # Se l'input è un indirizzo IP
            abuse_data = query_abuseipdb(abuseipdb_api_key, query)
            abuse_data["abuseipdb"]=abuse_data
            proxy_data = query_proxycheck(proxycheck_api_key, query)
            proxy_data["proxycheck"]=proxy_data
            vt_data = query_virustotalip(virustotal_api_key, query)
            vt_data["virustotal"]=vt_data
            cr_data = query_criminalip(criminalip_api_key, query)
            cr_data["criminalip"]=cr_data
            spur_data = get_data_from_spur(query)
            #print("va bene")
        elif re.match(domain_pattern, query):  # Se l'input è un dominio
            #print("non va bene")
            domain = query
            ips = get_domain_ips(domain)
            #vt_data =query_virustotald(virustotal_api_key,domain)
            for ip in ips:
                print(ip)
                abuse_data = query_abuseipdb(abuseipdb_api_key, ip)
                proxy_data = query_proxycheck(proxycheck_api_key, ip)
                vt_data =query_virustotalip(virustotal_api_key,ip)
                cr_data=query_criminalip(criminalip_api_key,ip)

    datalist=[]
    datalistcr=[]
    datalistvt=[]
    #print("Abuse data:")
    try:
        with open('dataabuse.json') as f_abuse:
            for line in f_abuse:
                data_abuse = json.loads(line)
                data_abusec = clean_query_result(data_abuse)
                #print(data_abusec)
                datalist.append(data_abusec)
    except Exception as e:
        print("Error loading dataproxy.json:", e)
    try:
        with open('dataproxy.json') as f_proxy:
            for line in f_proxy:
                data_proxy = json.loads(line)
                data_proxyc = clean_query_result(data_proxy)
                #print(data_proxyc)
                datalist.append(data_proxyc)
    except Exception as e:
        print("Error loading dataproxy.json:", e)
    #print(datalist)
    # Leggi e stampa i dati dal file JSON di proxy
    #print("Proxy data:")
    try:
        with open('datavt.json') as f_vt:
            for line in f_vt:
                data_vt = json.loads(line)
                datalistvt.append(data_vt)
        # Se il contenuto non è già una lista, inseriscilo in una lista
        if not isinstance(datalistvt, list):
            datalistvt = [datalistvt]
    except Exception as e:
        print("Error loading datavt.json:", e)
    #print(datalist)
    
    try:
        with open('datacr.json') as f_cr:
            for line in f_cr:
                data_cr = json.loads(line)
                datalistcr.append(data_cr)
            #print(datalistcr)
    except Exception as e:
        print("Error loading datacr.json:", e)
    f=0
    num_tables = len(datalist) // 2
    num_tablesvt =len(datalistvt)
    # Estrai i dati per le colonne
    range_parts = [re.search(r'(/\d+)', data['range']).group() for data in datalist[num_tables:]]
    queryrange =range_parts
    abuse_subnet = get_subnet_reports(query,queryrange)
    #range_parts=[data['range'] for data in datalist[num_tables:]]
    #print(range_parts)
    col_names = [data['ipAddress'] for data in datalist[:num_tables]]
    col_names_with_range = [f"{ip}{range_part}" for ip, range_part in zip(col_names, range_parts)]
    #print(col_names)
    # Estrai i dati per le righe
    proxy = [data['proxy'] for data in datalist[num_tables:]]
    abuseConfidenceScore = [data['abuseConfidenceScore'] for data in datalist[:num_tables]]
    lastVTanalysis = datalistvt[f]
    lastVTanalysis= lastVTanalysis['data']['attributes']['last_analysis_stats']
    lastVTanalysis = {key: lastVTanalysis[key] for key in list(lastVTanalysis)[:2]}
    lastVTanalysis = json.dumps(lastVTanalysis)
    crIpanalysis = datalistcr[f]['ip_scoring']['is_malicious']
    lastReportedAt = [data['lastReportedAt'] for data in datalist[:num_tables]]
    lastReportedAt = [data.split('T')[0] for data in lastReportedAt]
    provider = [data['provider'] for data in datalist[num_tables:]]
    organisation = [data['organisation'] for data in datalist[num_tables:]]
    countryCode = [data['countryCode'] for data in datalist[:num_tables]]
    country = [data['country'] for data in datalist[num_tables:]]
    region = [data['region'] for data in datalist[num_tables:]]
    domain = [data['domain'] for data in datalist[:num_tables]]
    usageType = [data['usageType'] for data in datalist[:num_tables]]
    isWhitelisted = [data['isWhitelisted'] for data in datalist[:num_tables]]
    hostnames = [data['hostnames'] for data in datalist[:num_tables]]
    openPorts = []
    a=0
    d=0
    b=len(datalistcr[f]['current_open_ports']['TCP'])
    #print(b)
    c=len(datalistcr[f]['current_open_ports']['UDP'])
    if b!= 0:
        for a in range(b):
            tcp_ports=datalistcr[f]['current_open_ports']['TCP'][a]['port']
            openPorts.append(tcp_ports)
    if c!= 0:
        for d in range(c):
            udp_ports=datalistcr[f]['current_open_ports']['UDP'][d]['port']
            openPorts.append(udp_ports)
    #print(openPorts)
    openPorts=str(openPorts)
    if crIpanalysis=='True':
        crIpanalysis='Malicious'
    else:
        crIpanalysis='not Malicious'
    f+=1
    # Crea il DataFrame
    df = pd.DataFrame({
        'IPAddress': col_names_with_range,
        'Proxy': proxy,
        'AbuseConfidenceScore': abuseConfidenceScore,
        'SpurCheck': spur_data,
        'lastVTanalysis': lastVTanalysis,
        'CrIpAnalysis' : crIpanalysis,
        'LastReportedAt': lastReportedAt,
        'Provider': provider,
        'Organisation': organisation,
        'CountryCode': countryCode,
        'Country': country,
        'Region': region,
        'Domain': domain,
        'UsageType': usageType,
        'IsWhitelisted': isWhitelisted,
        'Hostnames': hostnames,
        'openPorts': openPorts,
    })
    df.set_index('IPAddress', inplace=True)
    df = df.transpose()
    # Stampa il DataFrame
    print(df)
    print("Subnet Report: "+ abuse_subnet)
    '''
    print(json.dumps(datalist, indent=4))
    # Converti la lista di dati in un DataFrame
    dfall = pd.DataFrame(datalist)

    # Stampa il DataFrame
    print("DataFrame:")
    dfall.to_json('dfall.json', orient='records')
    print(dfall)
    '''
if __name__ == "__main__":
    main()
