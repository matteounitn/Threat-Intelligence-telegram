import requests
import json
from pyrogram import Client, filters
from pyrogram.errors.exceptions.bad_request_400 import MessageTooLong
import time

# importing uuid
import uuid
import os
import base64
import socket


def load_config():
    with open("config.json") as f:
        config = json.load(f)
    return config


def load_admins():
    with open("admins.json") as f:
        admins = json.load(f)
    return admins


def load_api_keys():
    with open("api_keys.json") as f:
        api_keys = json.load(f)

    assert api_keys['neutrino']['user-id'] and api_keys['neutrino']['api-key'], "Neutrino API keys not found"
    assert api_keys['alien_vault']['api-key'], "AlienVault API key not found"
    assert api_keys['pulsedive']['api-key'], "Pulsedive API key not found"
    assert api_keys['greynoise']['api-key'], "GreyNoise API key not found"
    assert api_keys['ip_data_co']['api-key'], "IPData.co API key not found"
    assert api_keys['abuseipdb']['api-key'], "AbuseIPDB API key not found"
    assert api_keys['ibm_xforce']['api-key'] and api_keys['ibm_xforce']['api-password'], "IBM X-Force API keys not found"
    
    return api_keys

api_keys=load_api_keys()

neutrino_user_id, neutrino_api_key = api_keys['neutrino']['user-id'], api_keys['neutrino']['api-key']
alien_vault_api_key = api_keys['alien_vault']['api-key']
admin = load_admins()["admin"]
pulsedive_api_key = api_keys['pulsedive']['api-key']
greynoise_api_key = api_keys['greynoise']['api-key']
ip_data_co_api_key = api_keys['ip_data_co']['api-key']
abuseipdb_api_key = api_keys['abuseipdb']['api-key']
ibm_xforce_api_key, ibm_xforce_api_password = api_keys['ibm_xforce']['api-key'], api_keys['ibm_xforce']['api-password']


def is_admin(user_id):
    #we return true if the user is admin or if the array is empty
    return str(user_id) in admin or not admin


def jsonformat(
    data,
    prefix="",
):
    # key in bold, value in normal
    string = []
    for key, value in data.items():
        if key == "sensors":
            string.append(f"{prefix}**{key}**: ")
            for i in value:
                for k, v in i.items():
                    string.append(f"{prefix}\t - **{k}**: {v}")
        else:
            if value:
                string.append(f"{prefix}**{key}**: {value}")
    return string


def pulsedive_formatter(response_json):
    out = []
    # Extract the required information from the JSON response
    risk = response_json["risk"] if "risk" in response_json else "None"
    risk_factors = (
        response_json["riskfactors"] if "riskfactors" in response_json else []
    )
    threats = response_json["threats"] if "threats" in response_json else []
    feeds = response_json["feeds"] if "feeds" in response_json else []
    whois = (
        response_json["properties"]["whois"]
        if "whois" in response_json["properties"]
        else {}
        if "whois" in response_json["properties"]
        else {}
    )
    # Save the information in an organized way
    out.append("**Risk**: " + risk)
    out.append("**Risk Factors**:")
    for rf in risk_factors:
        out.append(
            f"- {rf['description'] if 'description' in rf else 'None'} ({rf['risk'] if 'risk' in rf else 'None'})"
        )
    out.append("**Threats**:")
    for t in threats:
        out.append(
            f"- {t['name'] if 'name' in t else 'None'} - {t['category'] if 'category' in t else 'None'} ({t['risk'] if 'risk' in t else 'None'})"
        )
    out.append("**Feeds**:")
    for f in feeds:
        out.append(
            f"- {f['name'] if 'name' in f else 'None'} ({f['category'] if 'category' in f else 'None'}, {f['organization'] if 'organization' in f else 'None'})"
        )
    if whois:
        out.append("**Whois**:")
        out.append(
            f"- **Country**: {whois['country'] if 'country' in whois else 'None'}"
        )
        out.append(
            f"- **Organization**: {whois['organization'] if 'organization' in whois else 'None'}"
        )
        out.append(
            f"- **Address**: {whois['address'] if 'address' in whois else 'None'}"
        )
        out.append(f"- **City**: {whois['city'] if 'city' in whois else 'None'}")
        # registrant
        out.append(
            f"- **Registrant**: {whois['++registrant'] if '++registrant' in whois else 'None'}"
        )

    return out


def abuseipdb(ip, response_json, response_status):
    # Function to check IP reputation using AbuseIPDB
    out = []
    if response_status == 200:
        # example output
        out.append(f"**AbuseIPDB TI for {ip}:**")
        if "data" in response_json:
            if "abuseConfidenceScore" in response_json["data"]:
                out.append(
                    f"**Abuse Confidence Score**: {response_json['data']['abuseConfidenceScore']}%"
                )
            if "countryCode" in response_json["data"]:
                out.append(f"**Country Code**: {response_json['data']['countryCode']}")
            if "usageType" in response_json["data"]:
                out.append(f"**Usage Type**: {response_json['data']['usageType']}")
            if "isp" in response_json["data"]:
                out.append(f"**ISP**: {response_json['data']['isp']}")
            if "domain" in response_json["data"]:
                out.append(f"**Domain**: {response_json['data']['domain']}")
            if "hostnames" in response_json["data"]:
                out.append(f"**Hostnames**: {response_json['data']['hostnames']}")
            if "totalReports" in response_json["data"]:
                out.append(
                    f"**Total Reports**: {response_json['data']['totalReports']}"
                )
            if "numDistinctUsers" in response_json["data"]:
                out.append(
                    f"**Distinct Users**: {response_json['data']['numDistinctUsers']}"
                )
            if "lastReportedAt" in response_json["data"]:
                out.append(
                    f"**Last Reported At**: {response_json['data']['lastReportedAt']}"
                )
            if "reports" in response_json["data"]:
                out.append(f"**Last Three Reports' comments**:")
                out.append("```")
                for i in range(0, 3):
                    if i < len(response_json["data"]["reports"]):
                        out.append(
                            f"\t- {response_json['data']['reports'][i]['comment']if len(response_json['data']['reports'][i]['comment']) < 180 else response_json['data']['reports'][i]['comment'][:180] + '...'}"
                        )
                        out.append("")
                out.append("```")
    return out

def ibmxforce(ip, response_json, response_status):
    #we parse the history of the IP
    out = []
    out.append(f"**IBM X-Force TI for {ip}:**")
    if response_status == 200:
            if "cats" in response_json:
                out.append(f"**Categories**: {response_json['cats']}")
            if "history" in response_json:
                out.append(f"**History**:")
                #we want to print only the last 5 entries
                for h in response_json["history"]:
                    out.append(f"==> ({h['created']}) {h['ip']}:\n== **{h['reason']}**")
                    out.append(f"====> __{h['reasonDescription']}__")
                    if "cats" in h and len(h["cats"])>0:
                        out.append("====> **Categories**:")
                        for cat in h["cats"]:
                            out.append(f"======> **{cat}**: {h['cats'][cat]} __({h['categoryDescriptions'][cat]})__")
                            out.append("")
                    out.append("")
    return out

def ip_data_co(ip, response_json, response_status):
    # Function to check IP reputation using ipdata.co
    out = []
    if (
        response_status == 200
    ):  # we just want the threat and small information about country code and ASN
        # threat will be a dict
        out.append(f"**ipdata.co TI for {ip}:**")
        if "threat" in response_json:
            if "country_name" in response_json:
                out.append(f"**Country**: {response_json['country_name']}")
            if "asn" in response_json:
                if "asn" in response_json["asn"]:
                    out.append(f"**ASN**: {response_json['asn']['asn']}")
                if "name" in response_json["asn"]:
                    out.append(f"**ASN Name**: {response_json['asn']['name']}")
                if "domain" in response_json["asn"]:
                    out.append(f"**ASN Domain**: {response_json['asn']['domain']}")
                if "route" in response_json["asn"]:
                    out.append(f"**ASN Route**: {response_json['asn']['route']}")
                if "type" in response_json["asn"]:
                    out.append(f"**ASN Type**: {response_json['asn']['type']}")
                threat = response_json["threat"]

                out.append("**Threat**:")
                for key, value in threat.items():
                    if value and key != "blocklists":
                        out.append(f"- **{key}**: {value}")
                out.append("**Blocklist**:")
                for value in threat["blocklists"]:
                    out.append(f"\t {value['name']}")
                    out.append(f"\t\t- {value['site']}")
                    out.append(f"\t\t- {value['type']}")
    return out


# greynoise
def greynoise(ip, response_json, response_status):
    out = []
    if response_status == 200:
        out.append(f"**GreyNoise TI for {ip}:**")
        # Extract the required information from the JSON response
        noise = response_json["noise"] if "noise" in response_json else "None"
        riot = response_json["riot"] if "riot" in response_json else "None"
        classification = (
            response_json["classification"]
            if "classification" in response_json
            else "None"
        )
        name = response_json["name"] if "name" in response_json else "None"
        link = response_json["link"] if "link" in response_json else "None"
        last_seen = (
            response_json["last_seen"] if "last_seen" in response_json else "None"
        )
        message = response_json["message"] if "message" in response_json else "None"
        # Save the information in an organized way
        out.append("**IP**: " + ip)
        out.append("**Noise**: " + str(noise))
        out.append("**Riot**: " + str(riot))
        out.append("**Classification**: " + classification)
        out.append("**Name**: " + name)
        out.append("**Link**: " + link)
        out.append("**Last Seen**: " + last_seen)
        out.append("**Message**: " + message)
    elif response_status == 429:
        out.append("**IP**: " + ip)
        out.append("**Error**: Daily Rate-Limit Exceeded")
    elif response_status == 404:
        out.append("**IP**: " + ip)
        out.append("**Error**: IP not found in greynoise database")
    else:
        out.append("**IP**: " + ip)
        out.append("**Error**: " + str(response_status))

    return out


def check_ip_reputation(ip):
    ip_blocklist_neut = []
    dns_blocklist_neut = []
    pulsedive_ti = []
    ipdata = []
    abuseipdb_ti = []
    ibmxforce_ti = []
    otx_av = []
    gn = []
    raw = {}
    # Check IP against IP blocklist
    response = requests.get(
        "https://neutrinoapi.net/ip-blocklist",
        params={"user-id": neutrino_user_id, "api-key": neutrino_api_key, "ip": ip},
    )
    blocklist_info = json.loads(response.text)
    raw["ip-blocklist"] = blocklist_info.copy()
    if response.status_code == 200:
        ip_blocklist_neut.append(f"**IP address {ip} in IP blocklist:**")
        ip_blocklist_neut += jsonformat(blocklist_info)
    else:
        ip_blocklist_neut.append(f"**IP address {ip} in IP blocklist:**")
        ip_blocklist_neut.append(f"**Error**: {response.status_code}")

    # Check IP against DNS blocklist
    response = requests.get(
        "https://neutrinoapi.net/host-reputation",
        params={"user-id": neutrino_user_id, "api-key": neutrino_api_key, "host": ip},
    )
    dns_info = json.loads(response.text)
    if response.status_code == 200:
        listed_lists = []
        if "lists" in dns_info and dns_info["lists"]:
            listed_lists = [
                x
                for x in dns_info["lists"]
                if "is-listed" in x and x["is-listed"] == True
            ]
        raw["host-reputation"] = listed_lists.copy()
        dns_blocklist_neut.append(f"**IP address {ip} in DNS blocklist:**")
        for i in listed_lists:
            dns_blocklist_neut.append(
                f"\n{i['list-name'] if 'list-name' in i else 'None'}"
            )
            dns_blocklist_neut += jsonformat(i, prefix="\t - ")
    else:  # something went wrong
        raw["host-reputation"] = dns_info.copy()
        dns_blocklist_neut.append(f"**IP address {ip} in DNS blocklist:**")
        dns_blocklist_neut.append(
            f"**Error** {response.status_code}. You have exceeded the daily rate limit."
        )

    # Check IP against Pulsedive
    endpoint = "https://pulsedive.com/api/info.php"
    params = {"indicator": ip, "key": pulsedive_api_key, "pretty": 1}

    # Send the HTTP request and get the response
    response = requests.get(endpoint, params=params)
    response_json = response.json()
    raw["pulsedive"] = response_json.copy()

    pulsedive_ti.append(f"**IP address {ip} in Pulsedive:**")
    if "error" in response_json:
        if response_json["error"] == "Indicator not found.":
            pulsedive_ti.append(f"**IP address {ip} not found in Pulsedive**")
        elif response_json["error"] == "Invalid API key.":
            pulsedive_ti.append(f"**Invalid Pulsedive API key**")
        elif response_json["error"] == "Invalid indicator.":
            pulsedive_ti.append(f"**Invalid IP address**")
        elif response_json["error"] == "Rate limit exceeded.":
            pulsedive_ti.append(f"**Rate limit exceeded**")
        else:
            pulsedive_ti.append(f"**Unknown error**")
            print(response_json)
        pulsedive_ti.append(f"Try to open the link below to run the analysis:")
        base64ip = base64.b64encode(ip.encode("utf-8")).decode("utf-8")
        pulsedive_ti.append(f"https://pulsedive.com/indicator/?ioc={base64ip}")
    else:
        pulsedive_ti += pulsedive_formatter(response_json)
    # check greynoise

    response = requests.get(
        "https://api.greynoise.io/v3/community/" + ip,
        params={"key": greynoise_api_key},
    )
    response_json = json.loads(response.text)
    raw["greynoise"] = response_json.copy()
    gn = greynoise(ip, response_json, response.status_code)

    # ip reputation ipdata eu-api
    params = {"api-key": ip_data_co_api_key}
    response = requests.get(
        "https://eu-api.ipdata.co/" + ip,
        params=params,
    )
    response_json = json.loads(response.text)
    raw["ipdata"] = response_json.copy()
    ipdata = ip_data_co(ip, response_json, response.status_code)

    # Check IP against AbuseIPDB
    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
        headers={"Key": abuseipdb_api_key, "Accept": "application/json"},
    )
    abuseipdb_info = json.loads(response.text)
    # for the raw, we want to crop the verbose report part and keep only the first 3 reports
    
    if "reports" in abuseipdb_info:
        # we crop
        abuseipdb_info["reports"] = abuseipdb_info["reports"][:3]
    raw["abuseipdb"] = abuseipdb_info.copy()
    abuseipdb_ti = abuseipdb(ip, abuseipdb_info, response.status_code)

    # IBM X-Force Exchange
    
    response = requests.get(
        "https://api.xforce.ibmcloud.com/ipr/" + ip,
        auth=requests.auth.HTTPBasicAuth(ibm_xforce_api_key, ibm_xforce_api_password),
    )
    response_json = json.loads(response.text)
    raw["ibm_xforce"] = response_json.copy()
    ibmxforce_ti = ibmxforce(ip, response_json, response.status_code)

    # Check OTX Alienvault Tags for this IP
    headers = {"X-OTX-API-KEY": alien_vault_api_key}
    response = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers=headers,
    )
    try:
        otx_info = json.loads(response.text)
    except Exception as e:
        otx_info = {}
        print(e)
        print(response.text)
    raw["otx"] = otx_info.copy()
    tags = [tag for pulse in otx_info["pulse_info"]["pulses"] for tag in pulse["tags"]]
    otx_av.append("**OTX Alienvault Tags for this IP:**")
    # we want to remove duplicates
    tags = list(set(tags))
    otx_av.append(", ".join(tags))
    return [
        ip_blocklist_neut,
        dns_blocklist_neut,
        pulsedive_ti,
        gn,
        ipdata,
        abuseipdb_ti,
        ibmxforce_ti,
        otx_av,
    ], raw


# Initialize the Pyrogram client

app = Client("my_bot", **load_config())


def check_ip_validity(ip):
    # we parse the string to check if it is a valid ip
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def check_internal_ip(ip):
    # we check if it is an internal ip
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or ip.startswith("172.16.")
        or ip.startswith("172.17.")
        or ip.startswith("172.18.")
        or ip.startswith("172.19.")
        or ip.startswith("172.20.")
        or ip.startswith("172.21.")
        or ip.startswith("172.22.")
        or ip.startswith("172.23.")
        or ip.startswith("172.24.")
        or ip.startswith("172.25.")
        or ip.startswith("172.26.")
        or ip.startswith("172.27.")
        or ip.startswith("172.28.")
        or ip.startswith("172.29.")
        or ip.startswith("172.30.")
        or ip.startswith("172.31.")
        or ip.startswith("127.")
    )


# Define the message handler function
@app.on_message(filters.private & filters.regex(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"))
def handle_message(client, message):
    if is_admin(message.from_user.id):
        # we check if it is a valid ip
        if not check_ip_validity(message.text):
            message.reply_text(
                "Invalid IP address.\nJust write the IP address and nothing else.\nNo protocol, no port."
            )
            return
        # we check if it is an internal ip
        if check_internal_ip(message.text):
            message.reply_text("Internal IP address.")
            return
        message.reply_text("Checking IP...")
        ip = message.text
        print(
            f"Checking IP {ip}, requested by {message.from_user.id} ({message.from_user.first_name} {message.from_user.last_name})"
        )
        output, raw = check_ip_reputation(ip)
        for i in output:
            try:  # if message too long
                message.reply_text("\n".join(i), disable_web_page_preview=True)
            except MessageTooLong as m:
                print(m)
                message.reply_text("Message too long, sending a file:")
                # generating uuid
                uuid_string = str(uuid.uuid4())
                with open(f"output{uuid_string}.txt", "w") as f:
                    f.write("\n".join(i))
                message.reply_document(f"output{uuid_string}.txt")
                if os.path.exists(f"output{uuid_string}.txt"):
                    os.remove(f"output{uuid_string}.txt")
            time.sleep(0.5)
        # sending raw data
        # generating uuid for raw data
        uuid_string = str(uuid.uuid4())
        with open(f"raw_{ip}-{uuid_string}.json", "w") as f:
            json.dump(raw, f)
        message.reply_document(f"raw_{ip}-{uuid_string}.json")
        if os.path.exists(f"raw_{ip}-{uuid_string}.json"):
            os.remove(f"raw_{ip}-{uuid_string}.json")


# Start the client
app.run()
