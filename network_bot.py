import telegram
from telegram.ext import Updater, CommandHandler
import nmap

# Initialize the Telegram bot
TOKEN = '6042699403:AAHXmCfMUTk5FQKRRNqEldgRwEwwFXCC_60'
bot = telegram.Bot(token=TOKEN)

# Define the network scanning function
def scan_network(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments='-sS -O')
    result = ''
    for host in nm.all_hosts():
        result += f"Host : {host}\n"
        result += f"State : {nm[host].state()}\n"
        for proto in nm[host].all_protocols():
            result += "Protocol : {}\n".format(proto)
            lport = nm[host][proto].keys()
            for port in lport:
                result += f"port : {port}\tstate : {nm[host][proto][port]['state']}\n"
    return result

# Define the command handlers
def start(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Hi! I'm a network scanner bot. Use /help to see the available commands.")

def help(update, context):
    help_text = "/scan [ip_address] - Perform a network scan on the specified IP address.\n"
    help_text += "/status - Check the status of the bot.\n"
    help_text += "/restart - Restart the bot.\n"
    help_text += "/stop - Stop the bot."
    context.bot.send_message(chat_id=update.effective_chat.id, text=help_text)

def scan(update, context):
    ip_address = context.args[0]
    result = scan_network(ip_address)
    filename = f"{ip_address}_scan_result.txt"
    with open(filename, "w") as f:
        f.write(result)
    context.bot.send_document(chat_id=update.effective_chat.id, document=open(filename, 'rb'))
    context.bot.send_message(chat_id=update.effective_chat.id, text="Scan result saved in file: " + filename)

def status(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Bot is running.")

def stop(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Bot stopped.")
    updater.stop()

def restart(update, context):
    context.bot.send_message(chat_id=update.effective_chat.id, text="Bot restarting...")
    updater.start_polling()

# Initialize the command handlers and start the bot
updater = Updater(token=TOKEN, use_context=True)
dispatcher = updater.dispatcher
dispatcher.add_handler(CommandHandler('start', start))
dispatcher.add_handler(CommandHandler('help', help))
dispatcher.add_handler(CommandHandler('scan', scan))
dispatcher.add_handler(CommandHandler('status', status))
dispatcher.add_handler(CommandHandler('stop', stop))
dispatcher.add_handler(CommandHandler('restart', restart))
updater.start_polling()
updater.idle()
