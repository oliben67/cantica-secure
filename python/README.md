# cantica-secure (python)

Shimmable authentication/authorization core for Cantica servers.

```python
from fastapi import FastAPI
from cantica_secure import SecureConfig, SecurityShim

app = FastAPI()
SecurityShim(SecureConfig()).mount(app, prefix="/v1")
```

See the repository ROADMAP for the full design.
