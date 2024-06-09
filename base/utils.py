import requests
from django.core.cache import cache
from backend.settings import SELECTEL_API_URL, USERNAME, ACCOUNT_ID, PASSWORD, PROJECT_NAME

# SELECTEL_API_URL = "https://cloud.api.selcloud.ru/identity/v3/auth/tokens"
# USERNAME = "artem"
# ACCOUNT_ID = "322005"
# PASSWORD = "5809Art5809"
# PROJECT_NAME = "Storage"

def get_selectel_token():
    token = cache.get('selectel_token')
    if not token:
        response = requests.post(
            SELECTEL_API_URL,
            headers={"Content-Type": "application/json"},
            json={
                "auth": {
                    "identity": {
                        "methods": ["password"],
                        "password": {
                            "user": {
                                "name": USERNAME,
                                "domain": {"name": ACCOUNT_ID},
                                "password": PASSWORD
                            }
                        }
                    },
                    "scope": {
                        "project": {
                            "name": PROJECT_NAME,
                            "domain": {"name": ACCOUNT_ID}
                        }
                    }
                }
            }
        )

        if response.status_code == 201:
            token = response.headers['X-Subject-Token']
            cache.set('selectel_token', token, timeout=24*60*60 - 60)  # Токен живет 24 часа, обновляем за минуту до истечения
        else:
            raise Exception("Failed to obtain token: {}".format(response.text))

    return token
