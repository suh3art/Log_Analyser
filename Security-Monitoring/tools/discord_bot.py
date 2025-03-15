import discord
import asyncio
import os

TOKEN = "MTM1MDA4MTE1MzIwNTQwMzY2OA.GZz8oA.HrWJF2-nVhnrhKLRzdw_0-0oEZxz2P_xPl3JNY"  # Replace with your actual bot token, . 
CHANNEL_ID = 1336329946036961362  # Replace with the you Discord channel ID 

intents = discord.Intents.default()
client = discord.Client(intents=intents)

async def send_log_messages():
    await client.wait_until_ready()
    channel = client.get_channel(CHANNEL_ID)
    
    log_file = "../logs/simulated_attack.log"  # Adjust the log file path 
    last_position = 0
    
    while not client.is_closed():
        if os.path.exists(log_file):
            with open(log_file, "r") as file:
                file.seek(last_position)
                new_logs = file.readlines()
                last_position = file.tell()
            
            for log in new_logs:
                await channel.send(f"🚨 **New Attack Log Detected:**\n```{log}```")
        
        await asyncio.sleep(30)  # Check logs every 30 seconds

@client.event
async def on_ready():
    print(f"✅ Logged in as {client.user}")
    client.loop.create_task(send_log_messages())

client.run(TOKEN)
