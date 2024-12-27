import json
import uuid

with open('advisory.json', 'r') as file:
    data = json.load(file)

def replace_ids_with_uuids(data):
    def replace_in_url(url):
        base_url, record_id = url.rsplit('/', 1)
        new_uuid = str(uuid.uuid4())
        return f"{base_url}/{new_uuid}"
    
    if isinstance(data, list):
        for item in data:
            item['url'] = replace_in_url(item['url'])
            
            for package in item.get('fixed_packages', []):
                package['url'] = replace_in_url(package['url'])
            
            for package in item.get('affected_packages', []):
                package['url'] = replace_in_url(package['url'])
    else:
        print("Data is not a list as expected.")
    
    return data

updated_data = replace_ids_with_uuids(data)

with open('advisory.json', 'w') as file:
    json.dump(updated_data, file, indent=4)

print("URLs have been updated.")
