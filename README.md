# crypto-analysis

Set of tools include:
- Bytenigma implementation
- PKCS7 padding oracle attack (client + server)
- AES GCM ciphertext recovery for nonce reuse with Cantor-Zassenhaus

# Usage
`kauma` file is provided with eighter a path to a JSON file or raw JSON:
`./kauma anytask.json`

# JSON format
```
{
    "action": "gcm-recover",
    ...
}
```
