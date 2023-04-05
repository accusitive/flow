import requests
import os 
eula = """#By changing the setting below to TRUE you are indicating your agreement to our EULA (https://aka.ms/MinecraftEULA).
#Tue Apr 04 15:50:55 EDT 2023
eula=true
"""
print("Legally I have to say that by using this software you agree to the Minecraft EULA, https://aka.ms/MinecraftEULA. If you don't use CTRL C to exit")
paperConfig = """proxies:
  bungee-cord:
    online-mode: true
  proxy-protocol: false
  velocity:
    enabled: true
    online-mode: false
    secret: secret"""
version = input("What version?: ")
url = f"https://serverjars.com/api/fetchJar/servers/paper/{version}"
version_folder = f"./TestServer/{version}"
config_folder = f"./TestServer/{version}"

if not os.path.exists(version_folder):
    os.makedirs(version_folder)
if not os.path.exists(config_folder):
    os.makedirs(config_folder)
open(f"{version_folder}/paper.jar", 'wb').write(requests.get(url).content)
open(f"{version_folder}/paper.yml", "w").write(paperConfig)
open(f"{version_folder}/eula.txt", "w").write(eula)
open(f"{version_folder}/server.properties", "w").write("network-compression-threshold=-1\noonline-mode=false\nserver-port=25566")