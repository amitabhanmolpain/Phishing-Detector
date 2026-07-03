import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    google_safe_browsing_api_key: str | None = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY") or None
    cors_origins: list[str] = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
        if origin.strip()
    ]


settings = Settings()
