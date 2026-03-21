import asyncio
import aiohttp
import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def main():
    from custom_components.jellyha.api import JellyfinApiClient
    
    # We need the user and API key from the local HA state, but we can't easily import HA core things here without running inside it.
    # Alternatively we can just look at .storage/core.config_entries to get the API key.
    import json
    with open('/config/.storage/core.config_entries', 'r') as f:
        data = json.load(f)
    
    for entry in data['data']['entries']:
        if entry['domain'] == 'jellyha':
            api_key = entry['data']['api_key']
            server_url = entry['data']['server_url']
            user_id = entry['data']['user_id']
            break
            
    async with aiohttp.ClientSession() as session:
        api = JellyfinApiClient(server_url=server_url, api_key=api_key, session=session)
        views = await api.get_libraries(user_id)
        for view in views:
            print(f"Library: {view.get('Name')}, ID: {view.get('Id')}, CollectionType: {view.get('CollectionType')}")

if __name__ == "__main__":
    asyncio.run(main())
