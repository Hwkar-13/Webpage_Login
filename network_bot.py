import telebot
import nmap

# Replace with your Telegram Bot API token
TOKEN = '6042699403:AAHXmCfMUTk5FQKRRNqEldgRwEwwFXCC_60'

# Initialize the Telegram Bot
bot = telebot.TeleBot(TOKEN)

# Initialize the Nmap scanner
scanner = nmap.PortScanner()

# Define a function to handle the /start command
@bot.message_handler(commands=['start'])
def start(message):
    bot.reply_to(message, "Welcome to the network scanner bot! Use /help to see the available commands.")

# Define a function to handle the /help command
@bot.message_handler(commands=['help'])
def help(message):
    bot.reply_to(message, "/status - Check the status of the network scan\n/scan <IP_ADDRESS> - Start a network scan on the specified IP address\n/stop - Stop the current network scan\n/restart - Restart the current network scan")

# Define a function to handle the /status command
@bot.message_handler(commands=['status'])
def status(message):
    if scanner.is_scanning():
        bot.reply_to(message, "The network scan is currently running.")
    else:
        bot.reply_to(message, "The network scan is not currently running.")

# Define a function to handle the /scan command
@bot.message_handler(commands=['scan'])
def scan(message):
    try:
        # Extract the IP address from the command
        ip_address = message.text.split()[1]
        bot.reply_to(message, f"Starting network scan on {ip_address}...")
        
        # Scan the network
        scanner.scan(ip_address, arguments='-sS -T4')

        # Send the scan results to the user
        bot.reply_to(message, scanner[ip_address].all_protocols())
        bot.reply_to(message, scanner[ip_address]['tcp'])
    except:
        bot.reply_to(message, "Invalid command syntax. Use /scan <IP_ADDRESS> to start a network scan.")

# Define a function to handle the /stop command
@bot.message_handler(commands=['stop'])
def stop(message):
    if scanner.is_scanning():
        scanner.stop()
        bot.reply_to(message, "The network scan has been stopped.")
    else:
        bot.reply_to(message, "The network scan is not currently running.")

# Define a function to handle the /restart command
@bot.message_handler(commands=['restart'])
def restart(message):
    if scanner.is_scanning():
        scanner.stop()
        bot.reply_to(message, "The network scan has been stopped. Restarting...")
        scanner.scan(scanner.all_hosts(), arguments='-sS -T4')
        bot.reply_to(message, "The network scan has been restarted.")
    else:
        bot.reply_to(message, "The network scan is not currently running.")

# Start the Telegram Bot
bot.polling()
