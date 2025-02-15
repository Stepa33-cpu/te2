import os
import requests

# Base OneDrive URL
onedrive_url = 'https://graph.microsoft.com/v1.0/me/drive/'

def create_folder(access_token, folder_name, parent_folder_id='root'):
    """Create a folder on OneDrive if it doesn't exist"""
    url = f"{onedrive_url}items/{parent_folder_id}/children"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    data = {
        'name': folder_name,
        'folder': {},
        '@microsoft.graph.conflictBehavior': 'rename'
    }

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        return response.json()  # Return the folder metadata
    return None

def get_folder_id(access_token, folder_name):
    """Get the ID of a folder in OneDrive by its name"""
    url = f"{onedrive_url}root/children"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        folders = response.json().get('value', [])
        for folder in folders:
            if folder['name'] == folder_name:
                return folder['id']
    return None

def upload_file_to_onedrive(access_token, file_path, destination_folder_id='root'):
    """Upload a file to OneDrive"""
    filename = os.path.basename(file_path)
    url = f"{onedrive_url}items/{destination_folder_id}:/{filename}:/content"
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    with open(file_path, 'rb') as file:
        response = requests.put(url, headers=headers, data=file)

    if response.status_code == 201:
        print(f"File {filename} uploaded successfully.")
        return response.json()  # Return the file metadata
    else:
        print(f"Error uploading file: {response.status_code}, {response.text}")
        return None

def prepare_and_upload_file(access_token, file_path):
    """Prepare and upload the file to the correct folder on OneDrive"""
    fragments_folder_id = get_folder_id(access_token, 'fragments')
    if not fragments_folder_id:
        create_folder(access_token, 'fragments')
        fragments_folder_id = get_folder_id(access_token, 'fragments')

    # Assuming the file is fragmented or ready to be uploaded
    upload_file_to_onedrive(access_token, file_path, fragments_folder_id)
