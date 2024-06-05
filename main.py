import json
import os
import logging
import websockets
import hashlib
import asyncio
import traceback

import fortnitepy
import aiohttp
import crayons
import discord

from discord.commands import Option
from discord.ext import commands as DiscordCommands
from fortnitepy.ext import commands as FortniteCommands

class colors:
  default = 0
  teal = 0x1abc9c
  dark_teal = 0x11806a
  green = 0x2ecc71
  dark_green = 0x1f8b4c
  blue = 0x3498db
  dark_blue = 0x206694
  purple = 0x9b59b6
  dark_purple = 0x71368a
  magenta = 0xe91e63
  dark_magenta = 0xad1457
  gold = 0xf1c40f
  dark_gold = 0xc27c0e
  orange = 0xe67e22
  dark_orange = 0xa84300
  red = 0xe74c3c
  dark_red = 0x992d22
  lighter_grey = 0x95a5a6
  dark_grey = 0x607d8b
  light_grey = 0x979c9f
  darker_grey = 0x546e7a
  blurple = 0x7289da
  greyple = 0x99aab5

#Tokens for Auth Clients
NEW_SWITCH_TOKEN = "Basic OThmN2U0MmMyZTNhNGY4NmE3NGViNDNmYmI0MWVkMzk6MGEyNDQ5YTItMDAxYS00NTFlLWFmZWMtM2U4MTI5MDFjNGQ3"
IOSTOKEN = "Basic MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE="

CurrentBots = {} #stealing the same structure from Commando 💀
APIKEY = ""#Fortniteapi.io key (the better api) # nuh uh
nokickStatus = "Atomic NoKick |  {0}"
bot = DiscordCommands.Bot(
  command_prefix=[
    "a.",
    "A."
  ],
)

os.system("title No kick lobbybot")

def cls():
  os.system('cls' if os.name == 'nt' else 'clear')

def grey(string):
  output = crayons.white(string)
  return str(output)

def red(string):
  output = crayons.red(string)
  return str(output)

def yellow(string):
  output = crayons.yellow(string)
  return str(output)

def green(string):
  output = crayons.green(string)
  return str(output)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter(grey('[XIVY] [%(levelname)s] - %(message)s'))
ch.setFormatter(formatter)
logger.addHandler(ch)

async def BotDefinition(
  account_id,
  device_id,
  secret,
  user
):
  
  client = FortniteCommands.Bot(
    command_prefix="!",
    auth=fortnitepy.DeviceAuth(
      device_id=device_id,
      account_id=account_id,
      secret=secret
    )
  )
  
  @client.event
  async def event_ready():
    embed = discord.Embed(
      title="Client Launched!",
      description=f"Launched {client.user.display_name}!\npirxcy was here :)"
    )
    await client.set_presence("discord.gg/fndev")
    logger.info(f"{user.name} launched {client.user.display_name}")
    CurrentBots.update({user.id:client})
    await user.send(embed=embed)


  return client

#commando code cus i cba rewriting my own code

class configuration:
  """Interact With The Bot Configuration("config.json")"""
  def read():
    """Read The Configuration File"""
    with open("config.json") as config_file:
      config = json.load(config_file)
      return config

class autocomplete:
  async def return_skins():
    skins = []
    c = cosmetics.read()
    for cos in c:
      if cos.upper().startswith("CID_") or cos.upper().startswith("CHARACTER_"):
        skins.append(c[cos]['name'])
    return skins

  async def return_pickaxes():
    pickaxes = []
    c = cosmetics.read()
    for cos in c:
      if cos.upper().startswith("PICKAXE") or cos.upper().endswith("PICKAXE"):
        pickaxes.append(c[cos]['name'])
    return pickaxes

  async def return_backblings():
    backblings = []
    c = cosmetics.read()
    for cos in c:
      if cos.upper().startswith("BID_") or cos.upper().startswith("BACKPACK_"):
        backblings.append(c[cos]['name'])
    return backblings

  async def return_emotes():
    emotes = []
    c = cosmetics.read()
    for cos in c:
      if cos.upper().startswith("EID_"):
        emotes.append(c[cos]['name'])
    return emotes

  async def get_skins(ctx: discord.AutocompleteContext):
    """Returns a list of skins that begin with the characters entered so far."""
    return [skin for skin in await autocomplete.return_skins() if skin.lower().startswith(ctx.value.lower())]
    
  async def get_emotes(ctx: discord.AutocompleteContext):
    """Returns a list of emotes that begin with the characters entered so far."""
    return [emote for emote in await autocomplete.return_emotes() if emote.lower().startswith(ctx.value.lower())]

  async def get_pickaxes(ctx: discord.AutocompleteContext):
    """Returns a list of pickaxes that begin with the characters entered so far."""
    return [pickaxes for pickaxes in await autocomplete.return_pickaxes() if pickaxes.lower().startswith(ctx.value.lower())]

  async def get_backblings(ctx: discord.AutocompleteContext):
    """Returns a list of backblings that begin with the characters entered so far."""
    return [backblings for backblings in await autocomplete.return_backblings() if backblings.lower().startswith(ctx.value.lower())]

class COSMETIC:
  def __init__(
    self,
    data
  ):
    """This is For Cosmetics To Be Easier To Use *eg emote.name*"""
    self.data = data
    self.id = self.data['id']
    self.name = self.data['name']
    self.description = self.data['description']
    self.type = self.data['type']
    self.variants = self.data.get("styles")
    self.info = self.data

class cosmetics:
  """To Interact With The Cosmetics File(items.json) Mainly To Prevent Ratelimits I added this to prevent spamming the api!"""
  def read():
    """This returns all the cosmetics stored like the configuration class"""
    with open("items.json") as f:
      return json.load(f)

  async def check():
    """This Keeps on Checking For New Cosmetics Every 5 Minutes! Credit Baygamer For This Idea and for some of the code for this!"""
    try:
        async with aiohttp.ClientSession() as session:
          async with session.get(
            "https://fortnite-api.com/aes"
          ) as data:
            build_info = await data.json()
          lastUpdate = build_info['data']['lastUpdate']
        if lastUpdate != configuration.read().get('lastUpdate'):
          with open('config.json', 'r') as f:
              config = json.load(f)
          
          # Modify the value of a specific key in the JSON object
          config['lastUpdate'] = lastUpdate
          
          # Dump the modified JSON object back to the file
          with open('config.json', 'w') as f:
              json.dump(config, f,indent=2) 
          await cosmetics.store()#Updates items.json
          return True
        else:
          return False
    except Exception as error:
      logger.warning(red(f'An Error Occured in The Cosmetic Check Task!\nTraceback: {traceback.format_exc()}'))
      return False
  
  async def store():
    try:
      async with aiohttp.ClientSession() as session:
        async with session.request(
          method="GET",				
          url="https://fortniteapi.io/v2/items/list?lang=en",
          headers={"Authorization": "a3943405-bf7d48d0-e876bcac-41436b21"}
        ) as r:
          response = await r.json()
          cosmetics = {}
          for cosmetic in response['items']:
            cosmetics[cosmetic["id"]] = cosmetic
          with open("items.json", "w") as f:
            json.dump(cosmetics, f,indent=2)
            logger.info(green("Stored Cosmetics!"))
    except Exception as error:
      logger.warning(red(f'An Error Occured in The Cosmetic Store Task!\nTraceback: {error}'))

  def round(n):
    return (n // 10 + 1) * 10

  def checkExtend(n):
    return n % 10 == 0
  
  async def check_loop():
    checks=0
    while True:
      cosM = bot.loop.create_task(cosmetics.check())
      checks+=1
      if cosM:
        logger.warning(green(f"No New Cosmetics! [{checks}/{cosmetics.round(checks)}]"))
        await asyncio.sleep(300)# sleep 5m
      else:
        logger.warning(red(f"No New Cosmetics! [{checks}/{cosmetics.round(checks)}]"))
        if cosmetics.checkExtend(checks):
          await asyncio.sleep(600)#Sleep 10m
        else:
          await asyncio.sleep(300)#Sleep 5m
            
  async def search(name=None, id=None, type=None):
    items = cosmetics.read()
    for item in items:
        if (name and name.lower() == item.lower()) or (id and id.lower() == item.lower()):
            prefix = {
                "CID": "cid_",
                "BID": "bid_",
                "EID": "eid_",
                "PICKAXE": "pickaxe_",
                "CHARACTER": "character_",
                "BACKPACK": "backpack_"
            }.get(type.upper())
            if item.lower().startswith(prefix):
                return COSMETIC(items[item])
    return None

class EpicHandler:

  async def get_exchange(bearerToken):
    async with aiohttp.ClientSession() as session:
      async with session.get(
        url="https://account-public-service-prod.ol.epicgames.com/account/api/oauth/exchange",
        headers={
          "Authorization": "Bearer " + bearerToken,
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      ) as request:
        data = await request.json()

    exchangeCode = data['code']
    return exchangeCode

  async def authsToBearer(auths):
    async with aiohttp.ClientSession() as session:
      async with session.post(
        url="https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token",
        headers={
          "Authorization": IOSTOKEN,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        data=f"grant_type=device_auth&account_id={auths['account_id']}&device_id={auths['device_id']}&secret={auths['secret']}"
      ) as request:
        data = await request.json()
    
    bearerToken = data['access_token']
    return bearerToken

  async def get_device_code(bearer_token, account_id):
    async with aiohttp.ClientSession() as session:
      async with session.post(
        url="https://account-public-service-prod.ol.epicgames.com/account/api/public/account/" + account_id + "/deviceAuth",
        headers={
          "Authorization": "Bearer " + bearer_token,
          'Content-Type': 'application/json'
          
        }
      ) as response:
        newResponse = await response.json()
        data = newResponse
      
    try:
      auths = {
        "account_id": account_id,
        "device_id": data["deviceId"],
        "secret": data["secret"]
      }
      return auths
    except KeyError:
      return None
        
  
  async def create_login(device_code):
    """Creates Login From Device Code"""
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
          url="https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token",
          headers = {
            "Authorization": NEW_SWITCH_TOKEN,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          data=f"grant_type=device_code&device_code={device_code}",
          ssl=False
        ) as request:
          if request.status != 200:
            return None
          data = await request.json()
        
        
        async with session.get(
          url="https://account-public-service-prod.ol.epicgames.com/account/api/oauth/exchange",
          headers={"Authorization": f"Bearer {data['access_token']}"}
        ) as request:
            data = await request.json()
            exchange_code = data["code"]
        
        async with session.post(
          url="https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token",
          headers={
            "Authorization": IOSTOKEN,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          data=f"grant_type=exchange_code&exchange_code={exchange_code}"
        ) as request:
            data = await request.json()
            
    device_auth = await EpicHandler.get_device_code(
      data["access_token"],
      data["account_id"]
    )
    return device_auth

  async def get_client_credentials_token():
    """Generates A Client Credentials Token For Auth""" 
    async with aiohttp.ClientSession() as session:
      async with session.post(
        url="https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token",
        headers={
          "Authorization": NEW_SWITCH_TOKEN,
          "Content-Type": "application/x-www-form-urlencoded"
        }, 
        data="grant_type=client_credentials", 
        ) as response:
          data = await response.json()
          
    return data["access_token"]


  async def create_device_authorization(access_token: str):
    """Generates A Device Authorization Code For Auth"""
    async with aiohttp.ClientSession() as session:
      async with session.post(
        url="https://account-public-service-prod03.ol.epicgames.com/account/api/oauth/deviceAuthorization",
        headers={
          "Authorization": f"bearer {access_token}",
          "Content-Type": 'application/x-www-form-urlencoded'
        },
        data="prompt=login"
      ) as response:
        data = await response.json()
        
    return data["device_code"], data['verification_uri_complete']

  
  async def websocket(
    serviceUrl:str,
    MMSAuth:str,
    client
  ):
    """ws for matchmake"""
    websocket = await websockets.connect(
      uri="wss://fortnite-matchmaking-public-service-live-eu.ol.epicgames.com:443",
      extra_headers={"Authorization": MMSAuth}
    )
    latest_data = None
    while True:
      
      try:
        latest_data = await websocket.recv()
        logger.info("Websocket Recieved : " + latest_data)
        if 'queuedPlayers' in json.loads(latest_data)['payload']:
          await websocket .send(
            json.dumps(
              {
                "name": "Exec",
                "payload": {"command": "p.StartMatch"}
              }
            )
          )

      except websockets.ConnectionClosed:
        break
    
    data = json.loads(latest_data)
    try:
      currentSession = data['payload']['sessionId']
      async with aiohttp.ClientSession() as session:
        async with session.get(
          url=f"https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/matchmaking/session/{currentSession}",
          headers={"Authorization": client.http.get_auth('FORTNITE_ACCESS_TOKEN')},
          data={}
        ) as request:
          return await request.text()
    except KeyError:
      return None

  async def matchmake(
    client,
    parameters:dict
  ):
    async with aiohttp.ClientSession() as session:
      async with session.get(
        url = f"https://fngw-mcp-gc-livefn.ol.epicgames.com/fortnite/api/game/v2/matchmakingservice/ticket/player/{client.user.id}",
        headers={
          'Content-Type': 'application/json',
          "Authorization": client.http.get_auth('FORTNITE_ACCESS_TOKEN'),
          'User-Agent': client.http.user_agent,
        },
        params=parameters
      ) as request:
        logger.info("MatchMaking Ticket Response : " + await request.text())
        response = await request.json()
        if response.__contains__("errorMessage") and (response.get("errorMessage","").__contains__("'PLAY'") or response.get("errorMessage","").__contains__("Banned")):
          return response['errorMessage']

    payload = response['payload']
    signature = response['signature']
    serviceUrl = response['serviceUrl']
    plaintext = payload[10:20] + "Don'tMessWithMMS" + signature[2:10]
    
    data = plaintext.encode('utf-16le')
    hash_object = hashlib.sha1(data)
    hash_digest = hash_object.digest()
    
    checksum = __import__("base64").b16encode(hash_digest[2:10]).decode().upper()

    MMSAuth=f"Epic-Signed mms-player {payload} {signature} {checksum}"
    return await EpicHandler.websocket(
      serviceUrl=serviceUrl,
      MMSAuth=MMSAuth,
      client=client
    )
  
  async def checkMap(
    client,
    mapcode:str
  ):
    """Get Fortnite Map info Via Bearer"""
    async with aiohttp.ClientSession() as session:
      async with session.get(
        url=f"https://links-public-service-live.ol.epicgames.com/links/api/fn/mnemonic/{mapcode}", 
        headers={
          "Authorization": client.http.get_auth('FORTNITE_ACCESS_TOKEN'),
          'Content-Type': 'application/json',
          }
      ) as request:
        data = await request.json()
    
    return request

  async def getMapData(
    request,
    alldata:bool
  ):
    data = await request.json()
    if alldata:
      return data
    else:
      version = data.get('version', '1')
      project_id = data.get('metadata', {}).get('projectId', 'NONE')
      return project_id
  
  async def getNetCL(client):
    """Returns NetCL for bucket id"""
    async with aiohttp.ClientSession() as session:
      async with session.post(
        url="https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/matchmaking/session/matchMakingRequest",
        headers={
          "Authorization": client.http.get_auth('FORTNITE_ACCESS_TOKEN'),
          "Content-Type": "application/json",
        },
        data = json.dumps({
          "criteria": [],
          "openPlayersRequired": 1,
          "buildUniqueId": "",
          "maxResults": 1
        })
      ) as request:
        response = await request.json()
        text = await request.text()
    #logger.info("NetCL Response : "+ text)
    
    try:
      data = response[0]
      NetCL = data['attributes']['buildUniqueId_s']
      return NetCL
    except:
      logger.info("Error In NetCl Response Is : " + text)
    

class xivybots:
  
  def getAuths(userId:str):
    with open("users.json") as f:
      auths = json.load(f)
      
    return auths.get(userId)
  
  def storeAuths(
    userId,
    auths
  ):
    with open("users.json") as f:
      current = json.load(f)
      f.close()
    
    current.update(
      {
        userId:{
          "device_id": auths['device_id'],
          "account_id": auths['account_id'],
          "secret": auths['secret']
        }
      }
    )
    
    with open(
      "users.json",
      "w+"
    ) as f:
      json.dump(
        current,
        f,
        indent=2
      )
      return True
  
  def gather():
    bots = list(CurrentBots.keys)
    return [user for user in bots]
  
  async def stop(userId):
    client = CurrentBots.get(userId)
    await client.close()
    del CurrentBots[userId]
    return
  
  async def restart(userId):
    await xivybots.stop(userId=userId)
    
  
  async def botWaitKill(user):
    await asyncio.sleep(delay=7200)
    await xivybots.stop(userId=user.id)
    await user.send("Bot stopped!")
  
  async def validateAuthCode(code:str):
    async with aiohttp.ClientSession() as session:
      
      async with session.post(
        "https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token",
        data=f"grant_type=authorization_code&code={code}",
        headers={
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": "basic MzQ0NmNkNzI2OTRjNGE0NDg1ZDgxYjc3YWRiYjIxNDE6OTIwOWQ0YTVlMjVhNDU3ZmI5YjA3NDg5ZDMxM2I0MWE=",
        }
      ) as request:
        
        if request.status == 200:
          response = await request.json()
          return response
        elif request.status in [400,401,403,404,405]:
          return False
  
  async def generateAuths(validation):
    async with aiohttp.ClientSession() as session:
    
      async with session.post(
        f"https://account-public-service-prod.ol.epicgames.com/account/api/public/account/{validation['account_id']}/deviceAuth",
        headers={
          "Content-Type": "application/json",
          "Authorization": f"Bearer {validation['access_token']}",
        }
      ) as request:
        response = await request.json()
    
    auths = {
      "device_id": response['deviceId'],
      "account_id": response['accountId'],
      "secret": response['secret']
    }
    return auths
  
  async def stopbot(userId:str):
    client = CurrentBots.get(userId)
    
    await client.stop()
    del CurrentBots[userId]
    
    return True



@bot.event
async def on_ready():
  cls()
  logger.info(grey('Launching Start Tasks!'))
  bot.loop.create_task(cosmetics.check_loop())
  return logger.info(green('All Tasks Done Successfully! Bot is Online!'))

@bot.slash_command(name="stopbot")
async def slash_stopbot(ctx):
  client = CurrentBots.get(ctx.author.id)
  if client:
    await xivybots.stop(ctx.author.id)
    embed = discord.Embed(title="Stopped!")
    await ctx.respond(embed=embed)
  else:
    embed = discord.Embed(title="You need a bot to stop!")
    await ctx.respond(embed=embed)
    
@bot.slash_command(name="login")
async def slash_device_login(ctx):
  token = await EpicHandler.get_client_credentials_token()
  device_code, url = await EpicHandler.create_device_authorization(token)  
  
  embed = discord.Embed(
    title="Login To Your Epic Games Account",
    url=url,
    color=colors.blurple
  )
  embed.add_field(
    name="Please Login Using The Following Info",
    value="1. Click The Button Below To Login To Your Epic Games Account\n2. Press Confirm\n3. Wait For The Bot To Log You In"
  )
  
  view = discord.ui.View()
  style = discord.ButtonStyle.gray 
  item = discord.ui.Button(
    style=style,
    label="Login To Epic",
    url=url
  )
  view.add_item(item)
  
  msgmsg = await ctx.respond(
    embed=embed, 
    view=view
  )

  logged_in = False
  disp = "" 
  async def check_if_logged_in():
    nonlocal logged_in
    attemps = 0
    while not logged_in:
      auth = await EpicHandler.create_login(device_code=device_code)
      attemps +=1
      logger.info(auth)
      if auth != None:
        xivybots.storeAuths(
          ctx.author.id,
          auths=auth
        )
        logged_in = True
      else:
        if attemps > 10:
          return
        await asyncio.sleep(3)
        
  thread = bot.loop.create_task(check_if_logged_in())
  await thread
  if logged_in:
    embed = discord.Embed(
      title="Logged In",
      description="Logged in !", 
      color=colors.green
    ) 
    await msgmsg.edit(
      embed=embed,
      view=None
    )
  else:
    embed = discord.Embed(
      title="Canceled Login", 
      description="You took too long!", 
      color=colors.red
    )
    await msgmsg.edit(
      embed=embed, 
      view=None
    )



@bot.slash_command(name="login-authcode")
async def slash_login(
  ctx,
  authcode: Option(
    str,
    "Enter your Authorizaion Code.",
  )
):
  InvalidEmbed = discord.Embed(title="Invalid Authorization Code")
  if len(authcode) != 32:
    await ctx.respond(embed=InvalidEmbed)
  else:
    valid = await xivybots.validateAuthCode(code=authcode)
    
    if not valid:
      await ctx.respond(embed=InvalidEmbed)
    else:
      
      auths = await xivybots.generateAuths(valid)
      xivybots.storeAuths(
        ctx.author.id,
        auths
      )
      embed = discord.Embed(
        title="Success!",
        description="run /startbot"
      )
      await ctx.respond(embed=embed)

@bot.slash_command(name="startbot")
async def slash_startbot(ctx):
  auths = xivybots.getAuths(str(ctx.author.id))
  if not auths:
    embed = discord.Embed(
      title="Error",
      description="Do /login first :)"
    )
    await ctx.respond(embed=embed)
  
  elif CurrentBots.get(ctx.author.id):
    embed = discord.Embed(
      title="Error",
      description="You already have a bot."
    )
    await ctx.respond(embed=embed)
    
  else:    
    client = await BotDefinition(
      user=ctx.author,
      account_id=auths.get("account_id"),
      device_id=auths.get("device_id"),
      secret=auths.get("secret"),
    )
    bot.loop.create_task(client.start())
    
    embed = discord.Embed(title="launching...\ncheck your dms for bot info")
    await ctx.respond(embed=embed)
    bot.loop.create_task(xivybots.botWaitKill(user=ctx.author))

@bot.slash_command(name="level")
async def slash_level(
  ctx,
  level: Option(
    int,
    "Enter a level."
  )
):
  if CurrentBots.get(ctx.author.id):
    client = CurrentBots[ctx.author.id]
    await client.party.me.set_banner(season_level=level)
    embed = discord.Embed(
      title="Success!",
      description=f"Level set to {level}"
    )
    await ctx.respond(embed=embed)
  else:
    await ctx.respond("You need a bot for this.")

@bot.slash_command(name="skin")
async def slash_skin(
  ctx, 
  *, 
  skin: Option(str, "Enter a skin", autocomplete=autocomplete.get_skins)
):
  """Sets The Skin"""
  client = CurrentBots.get(ctx.author.id)
  if client:
    items = cosmetics.read()
    
    for cosmetic in items:
      item = items[cosmetic]
      if (item['id'].upper().startswith("CID_") or item['id'].upper().startswith("CHARACTER_")) and (item['name'].upper().startswith(skin.upper()) or item['name'].lower() == skin.lower()):
        typeCosmetic = item
      else:
        continue
    
    await client.party.me.set_outfit(asset=typeCosmetic['id'])
    await ctx.respond(f"Skin set to {typeCosmetic['name']}")
      
      
  else:
    await ctx.respond("You need a bot for this.")
    
@bot.slash_command(name="emote")
async def slash_emote(
  ctx, 
  *, 
  emote: Option(str, "Enter a emote", autocomplete=autocomplete.get_emotes)
):
  """Sets The Emote"""
  client = CurrentBots.get(ctx.author.id)
  if client:
    items = cosmetics.read()
    typeCosmetic = None
    for cosmetic in items:
      item = items[cosmetic]
      if item['id'].upper().startswith("EID_") and (item['name'].upper().startswith(emote.upper()) or item['name'].lower() == emote.lower()):
        typeCosmetic = item
      else:
        continue
    
    info = await cosmetics.search(id=typeCosmetic['id'],type="EID")
    path = info.info['path']
    path +="."+typeCosmetic['id']
    await client.party.me.set_emote(asset=path)
    await ctx.respond(f"Emote set to {typeCosmetic['name']}")
      
      
  else:
    await ctx.respond("You need a bot for this.")

@bot.slash_command(name="restart")
async def slash_restart(ctx):
  client = CurrentBots.get(ctx.author.id)
  if client:
    await ctx.respond("Restarted!")
    await client.restart()
  else:
    await ctx.respond("You need a bot for this!")

@bot.slash_command(name="leave")
async def slash_restart2(ctx):
  client = CurrentBots.get(ctx.author.id)
  if client:
    await ctx.respond("Left!")  
    await client.restart()
  else:
    await ctx.respond("You need a bot for this!")



@bot.slash_command(name="nokick")
async def slash_nokick(
  ctx,
  mapcode: Option(
    str,
    "Enter a Map Code.",
    required=True
  ),
  region: Option(
    str,
    "Enter your current region.",
    autocomplete=discord.utils.basic_autocomplete(
      [
        "Europe", 
        "NA-East",
        "Oceania",
        "NA-West",
        "Brazil",
        "Middle East",
        "Asia",
        "NA-Central",

      ]
    ),
    required=True
  ),
  privategame: Option(
    bool,
    "Launch a Private Game?",
    required=True
  ),
):
  client = CurrentBots.get(ctx.author.id)
  if client:
      
    if not client.party.me.leader:
      await client.party.me.leave()
      embed = discord.Embed(
        title="Restart the Command!",
        description=f"You're already in game.\nPlease Run the Command again as I was not party leader."
      )
      return await ctx.respond(embed=embed)
      
    regionDict = {
      "EUROPE": "eu", 
      "NA-EAST": "nae",
      "OCEANIA": "oce",
      "NA-WEST": "naw",
      "BRAZIL": "br",
      "MIDDLE EAST": "me",
      "ASIA": "asia",
      "NA-CENTRAL": "nac",
    }
    
    chosenRegion = regionDict.get(region.upper())
    if not chosenRegion:
      regionText = f"Please Choose a valid Region.\n"
      for regionOption in list(regionDict.keys()  ):
        regionText += f"`{regionOption}` "
      embed = discord.Embed(
        title="Restart the Command!",
        description=regionText
      )
      return await ctx.respond(embed=embed)
    
    
    
    if "-" not in mapcode:
      mapcode = mapcode[:4] + '-' + mapcode[4:8] + '-' + mapcode[8:] 
      
    embed = discord.Embed(
      title="Generating",
      description=f"Please wait while we generate the match for you."
    )
    await ctx.respond(embed=embed)
    
    NetCL = await EpicHandler.getNetCL(client=client)
    if not NetCL:
      embed = discord.Embed(
        title="Error",
        description="Login Is Banned or The Profile Is Not Valid, Please Use The Command `/launch` And Load Up The Account, Then Play A Game On The Account To Correct This!",
      )
      return await ctx.respond(embed=embed)
    bucketId = f"{NetCL}:1:{chosenRegion.upper()}:noplaylist"
    
    if client.party.me.leader and len(client.party.members) != 1:
      for member in client.party.members:
        if member.id == client.user.id:
          continue
        
        await member.kick()
        
    mapRequest = await EpicHandler.checkMap(
      client=client,
      mapcode=mapcode,
    )
    mapData = await EpicHandler.getMapData(
      request=mapRequest,
      alldata=True
    )
        
    if mapRequest.status != 200:
      embed = discord.Embed(
        title="Error Finding Map!",
        description=f"Error Finding `{mapcode}`! Reason: Map Couldnt Be Found, Please Use Maps From https://fortnite.gg/creative?type=uefn",
      )
      return await ctx.respond(embed=embed)
    
    
    parameters = {
      "partyPlayerIds": [client.user.id],
      "bucketId": bucketId,
      "player.platform": "Android",
      "player.input": "KBM",
      "player.option.preserveSquad": "true",
      #"player.option.bots": "true",
      "player.option.partyld": client.party.id,
      "player.option.linkCode": mapcode,
      "player.option.groupBy": mapcode,
      "player.option.privateMMS": "true" if privategame else "false",
    }
    if "projectId" in mapData['metadata']:
      parameters["player.option.projectId"] = mapData['metadata']['projectId']
    
    
    request = await EpicHandler.matchmake(
      client,
      parameters=parameters
    )
    
    if not request:
      embed = discord.Embed(
        title="Error",
        description="The Profile Is Not Valid, Please Use The Command `/launch` And Load Up The Account To Correct This!",
      )
      return await ctx.respond(embed=embed)
    if request.__contains__("Banned"):
      embed = discord.Embed(
        title="Error",
        description="The Account Is Banned From Matchmaking, Please Use A Different Account!",
      )
      return await ctx.respond(embed=embed)
    elif request.__contains__("'PLAY'"):
      embed = discord.Embed(
        title="Error",
        description="Login Is Banned or The Profile Is Not Valid, Please Use The Command `/launch` And Load Up The Account, Then Play A Game On The Account To Correct This!",
      )
      return await ctx.respond(embed=embed)

    data = json.loads(request)
    status = nokickStatus.format(mapData['metadata']['title'])
    
    await client.set_presence(status)
    await client.send_presence(
      {
        "Status": status,
        "bIsPlaying": True,
        "bIsJoinable": True,
        "SessionId": data['id'],
        "Properties": {
          "_s": mapcode,
          "InUnjoinableMatch_b": False,
          "party.joininfodata.286331153_j": {
            "bIsPrivate": True
          },
          "ServerPlayerCount_i": 1,
          "GamePlaylistName_s": "Playlist_VK_Play",
          "Event_PartyMaxSize_s": "16",
          "Event_PartySize_s": "1",
          "Event_PlayersAlive_s": "1",
          "GameSessionJoinKey_s": data["attributes"]['SESSIONKEY_s']
        }
      }
    )
    embed = discord.Embed(
      title="Matchmaking",
      description=f"You can now join my game on Fortnite! Use /leave to leave the game when you are done."
    )
    embed.add_field(
      name="Map Code",
      value=mapcode,
      inline=True
    )
    embed.add_field(
      name="Map Name",
      value=mapData['metadata']['title'],
      inline=True
    )
    await ctx.respond(embed=embed)
    
    
  else:
    await ctx.respond("You need a bot for this")

@bot.slash_command(name="addfriend")
async def slash_addfriend(
  ctx,
  user: Option(
    str,
    "Enter the user or account id."
  )
):
  client = CurrentBots.get(ctx.author.id)
  if client:
    isAccountId = bool(len(user) == 32)
    try:
      if isAccountId:
        await client.add_friend(user)
      else:
        friend = await client.fetch_profile(user)
        await client.add_friend(friend.id)
    

      embed = discord.Embed(
      title="Added!",
      description=f"Sent a friend request to {user}"
    )
      await ctx.respond(embed=embed)
    except Exception as exc:
      embed = discord.Embed(
      title="Error!",
      description=f"Error: {str(exc)}"
    )

    
    
  else:
    await ctx.respond("You need a bot for this")

@bot.slash_command(name="launch")
async def slash_launch(
  ctx,
  fortnitepath: Option(
    str,
    "Your fortnite path.",
    required=False
  ),
  additional_args: Option(
    str,
    "Additional arguments.",
    required=False
  )
):
  if not additional_args:
    additional_args = ""
  
  if not fortnitepath:
    fortnitepath = '"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64"'
  elif fortnitepath.__contains__("\\") or fortnitepath.__contains__("/"):
    fortnitepath = f'"{fortnitepath}"'
  else:
    fortnitepath = '"C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64"'

  auths = xivybots.getAuths(str(ctx.author.id))
  bearerToken = await EpicHandler.authsToBearer(auths=auths)
  exchangeToken = await EpicHandler.get_exchange(bearerToken=bearerToken)

  embed = discord.Embed(
    title="Launch Fortnite on your bot account",
    description=f"Copy the following text into Command Prompt (cmd.exe) and hit enter. Valid for 5 minutes or until it is used.\n```bat\nstart /d {fortnitepath} FortniteLauncher.exe -AUTH_LOGIN=unused -AUTH_PASSWORD={exchangeToken} -AUTH_TYPE=exchangecode -epicapp=Fortnite -epicenv=Prod -EpicPortal -epicuserid={auths['account_id']} {additional_args}```"
  )
  await ctx.respond(embed=embed)

bot.run("token")