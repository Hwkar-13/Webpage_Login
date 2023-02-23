import telepot
import nmap
# Define your bot API token
bot_token = '6042699403:AAHXmCfMUTk5FQKRRNqEldgRwEwwFXCC_60'
# Create a connection to the Telegram bot API
bot = telepot.Bot(bot_token)
# Define a function to scan the network and return the results
def scan_network():
    nm = nmap.PortScanner()
    nm.scan('192.168.0.0/24', arguments='-p 22')
    return nm.all_hosts()
# Define a function to send the results to the user via Telegram
def send_results(chat_id, results):
    message = 'Network scan results:\n'
    message += '\n'.join(results)
    bot.sendMessage(chat_id, message)
# Define a function to handle incoming Telegram commands
def handle_command(msg):
    chat_id = msg['chat']['id']
    command = msg['text']
    if command == '/scan':
        results = scan_network()
        send_results(chat_id, results)
    else:
        bot.sendMessage(chat_id, 'Unknown command')
# Start the bot and listen for incoming messages
bot.message_loop(handle_command)
