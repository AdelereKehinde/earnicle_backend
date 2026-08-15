import asyncio, os, json
from datetime import datetime, timedelta, timezone
from jose import jwt
import httpx

EMAIL = "adelerekehinde02@gmail.com"
JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET:
    print('No JWT_SECRET in environment; aborting')
    raise SystemExit(1)

payload = {
    'sub': EMAIL,
    'type': 'reset',
    'exp': int((datetime.now(timezone.utc) + timedelta(minutes=15)).timestamp()),
    'iat': int(datetime.now(timezone.utc).timestamp())
}

token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
print('Generated token:', token)

async def main():
    async with httpx.AsyncClient() as c:
        r = await c.post('http://127.0.0.1:8000/auth/reset-password', json={
            'email': EMAIL,
            'reset_token': token,
            'new_password': 'TestReset123!'
        })
        print('Status:', r.status_code)
        try:
            print('Body:', r.json())
        except Exception:
            print('Body:', r.text)

asyncio.run(main())
