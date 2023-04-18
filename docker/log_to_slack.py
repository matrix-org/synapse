import subprocess
from slack_sdk import WebClient

log_file = open("/var/log/cron.log", "r")
logs = log_file.read()
log_file.close()

lastLog = logs.split("----- [")[-1]
message = "```----- [" + lastLog + "```"
channel = "YOUR_SLACK_CHANNEL"
token = "YOUR_SLACK_TOKEN"

diskUsage = "```" + subprocess.check_output(["df", "-h"]).decode("utf-8") + "```"

client = WebClient(token=token)
client.chat_postMessage(channel=channel, message=message)
client.chat_postMessage(channel=channel, text=diskUsage)
