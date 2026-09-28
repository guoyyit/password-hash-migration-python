
from credvault.api import create_app

app = create_app()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
