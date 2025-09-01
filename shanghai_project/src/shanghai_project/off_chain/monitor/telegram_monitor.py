from telethon import events
# from ftrading.setting import PROJECT_ROOT
# import os
from ftrading.monitor.telegram_client import client

chats_to_monitor = [
    # -1001441802238,
    -1001343688547,
]

def start_telegram_monitor(callback, client):
    # Ensure the session directory exists
    # session_dir = os.path.join(PROJECT_ROOT, 'data/session')
    # if not os.path.exists(session_dir):
    #     os.makedirs(session_dir)

    @client.on(events.NewMessage(chats=chats_to_monitor))
    async def handler(event):
        post_time = event.date  # This is a datetime object (UTC)
        entity_id = event.sender_id  # This is the sender's ID
        print(f"New message from {event.chat_id}: {event.text}")
        print(f"Posted at: {post_time}, by entity_id: {entity_id}")
        if callback:
            await callback({
                "text": event.text,
                "post_time": post_time,
                "entity_id": entity_id
            })

    print(f"Monitoring messages from: {chats_to_monitor} ...")
    # Do NOT call run_until_disconnected() here

if __name__ == "__main__":
    import asyncio
    async def startup():
        await client.start()
        start_telegram_monitor(callback=None, client=client)
        await client.run_until_disconnected()
    asyncio.run(startup())
