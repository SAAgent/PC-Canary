import requests
def unset_proxy():
    import os 
    # unset proxy
    os.environ['http_proxy'] = ''
    os.environ['https_proxy'] = ''

unset_proxy()

resp = requests.post("http://localhost:8765", json={
    "action": "deckNames",
    "version": 6
})
default_deck_name = resp.json()["result"][0]
for i in range(10):
    response = requests.post("http://localhost:8765", json={
        "action": "addNote",
        "version": 6,
        "params": {
            "note": {
                "deckName": default_deck_name,      # 改成你自己的笔记本名称
                "modelName": "问答题",       # 改成你使用的模板名
                "fields": {
                    "正面": f"What is this? {i}",
                    "背面": ""
                },
            }
        }
    })