# ncanode_client

## Installation
```bash
pip install git+ssh://git@github.com/aibaq/ncanode_client.git@0.1.0
```


## Basic usage

```python
from ncanode_client import NCANodeClient

client = NCANodeClient(base_url="https://self-hosted.ncanode.kz")
response = client.xml_verify(xml="signed xml value")

```

## Compatibility
Python 3.8+

## Tests
```bash
tox
```
