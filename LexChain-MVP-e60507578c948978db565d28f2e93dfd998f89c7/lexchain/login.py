import os

import msal
import requests
import webbrowser

APPLICATION_ID = '969255ff-912a-4f81-b038-4a7ff47f44f1'
CLIENT_SECRET = 'xwl8Q~jdqAIYYazJrdPIakmRcOJv0eg0HVsXxaKQ'
AUTHORITY_URL = 'https://login.microsoftonline.com/consumers/'

base_url = 'https://graph.microsoft.com/v1.0/'
endpoint = base_url + 'me'

SCOPES = ['Files.ReadWrite', 'User.Read']

client_instance = msal.ConfidentialClientApplication(
    client_id = APPLICATION_ID,
    client_credential = CLIENT_SECRET,
    authority = AUTHORITY_URL
)

authorization_request_url = client_instance.get_authorization_request_url(SCOPES)
print(authorization_request_url)
webbrowser.open_new_tab(authorization_request_url)

authorization_code = 'M.C537_SN1.2.U.f8e7f4e8-6632-a768-ebec-a9a18e0ec9b6'
access_token = client_instance.acquire_token_by_authorization_code(
    code=authorization_code,
    scopes=SCOPES,
)

access_token_id = access_token['access_token']
print(access_token)
headers = {
    'Authorization': 'Bearer ' + access_token_id,
    'Content-Type': 'application/json'
}


response = requests.get(endpoint, headers=headers)
print(response.json())
print(response)

#Am facut un folgher

data = {
    "name": "LexChain",  # Change folder name as needed
    "folder": {},
    "@microsoft.graph.conflictBehavior": "rename"  # Avoid conflicts
}

# Headers
headers = {
    "Authorization": f"Bearer {access_token_id}",
    "Content-Type": "application/json"
}

# Send the POST request
response = requests.post(endpoint, json=data, headers=headers)

# Print the response
if response.status_code == 201:
    print("Folder created successfully:", response.json())
else:
    print("Error:", response.status_code, response.text)


#Dam upload la poze xd 
file_path = r'C:\Users\bistr\Desktop\lexchain front\LCMVP\lexchain\uploads\1.png'
file_name = os.path.basename(file_path)

with open(file_path, 'rb') as upload:
    media_content = upload.read()

response = requests.put(
    base_url + f'/me/drive/root:/Salut/{file_name}:/content',
    headers = headers,
    data=media_content,
)
print(response.json())


# File details
file_name = "1.png"  # Change to your actual file name
save_path = os.path.join(r"C:\Users\bistr\Desktop", file_name)  # Local save path

# Microsoft Graph API file download URL
base_url = "https://graph.microsoft.com/v1.0"
download_url = f"{base_url}/me/drive/root:/Saluk/{file_name}:/content"

# Headers (Requires a valid access token)
headers = {
    "Authorization": f"Bearer {access_token_id}"
}

# Make request to download the file
response = requests.get(download_url, headers=headers, stream=True)

if response.status_code == 200:
    # Save the file locally
    with open(save_path, "wb") as file:
        for chunk in response.iter_content(chunk_size=8192):
            file.write(chunk)
    print(f" Download successful: {save_path}")
else:
    print(f" Error: {response.status_code}, {response.json()}")

