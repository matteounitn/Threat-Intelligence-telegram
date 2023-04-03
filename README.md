# Threat-Intelligence-telegram
A bot to quickly get information about an IP, useful to get threat intelligence informations for blue team.

## Example output

<img src="poc_TI.GIF" alt="poc" style="max-width:400px" />

## How to
### Step 0 

`git clone https://github.com/matteounitn/Threat-Intelligence-telegram.git`

### Step 1

- Go to https://my.telegram.org/auth?to=apps;
- Create an app(doesn't matter how do you call it);
- Get API ID and API KEYS;
- Replace them in `config.json.sample` and save it as `config.json`

### Step 2
#### Populate the various API Keys

You should register to:
- https://pulsedive.com (api-key)
- https://abuseipdb.com (api-key)
- https://greynoise.io (api-key)
- https://ipdata.co (api-key)
- https://otx.alienvault.com (api-key)
- https://neutrinoapi.com (user-id and api-key) ((PLEASE DO NOT USE ROOT KEY FOR THIS, create one api-key for the bot)
- https://exchange.xforce.ibmcloud.com (api-key and api-password)
- https://threatbook.io (api-key)
- https://www.virustotal.com (api-key)

**Get api-keys and api-password or user-id when needed.**

**They are all almost free**, i suggest you to register to neutrinoapi.com and pay for it, since it's very cheap. 

_If you don't want to use neutrinoapi (shame on you, it is one of the best) just comment the part of the code about neutrino and add a bogus api-key. Or just don't, the script should be failsafe, a bogus api-key will get a "unauthorized" response from neutrino._

Replace them in `api_keys.json.sample` and save it as `api_keys.json`

### Step 3
#### Create a bot

Create a telegram bot from the BotFather (https://t.me/botfather) and start a chat with it.

The url of your newly created bot will look like http://t.me/your_bot_name

Copy the APItoken generated by the BotFather, and add it in `config.json` as `bot_token`.

#### Get your user ID and set yourself as admin

Copy `admin.json.sample` and save it as `admin.json`.

Use `@getmyid_bot` bot to get your user ID. 
Should be in the form 
```
Your user ID: XXXXXXXXX 
Current chat ID: XXXXXXXXX
```
add the ID (doesn't matter which one, they should be the same) to admin.json (i.e., just change series of zero '000000000' in the file admin.json)
You can have more than one admin, just treat the admin.json as an array

```
{
 ["FIRST_ID", "SECOND_ID"]
}
```
**This lets people use your bot.**

If you want it to be used by everyone, just use an empty array 
```
{
 []
}
```
### Step 4
#### Run with docker
1. `cd Threat-Intelligence-telegram`
2. `docker build --no-cache -t my_ip_threat .`
3. `docker run --name ip_threat_check -d my_ip_threat`

Enjoy!

#### Run without docker
1. `cd Threat-Intelligence-telegram`
2. `sudo apt install python3-dev python3-venv`
3. `python3 -m venv venv`
4. `source venv/bin/activate`
5. `pip3 install -r requirements.txt`
6. `python3 run.py`
