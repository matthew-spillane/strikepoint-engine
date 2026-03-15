import os


class Settings:
    """Centralized configuration loaded from environment variables.

    All API keys are read via properties so they resolve at access time,
    not at class-definition / import time. This ensures env vars injected
    by the runtime (e.g. Railway) are picked up even if they are set after
    the module is first imported.
    """

    # --- API key properties (resolved at access time) ---
    @property
    def VIRUSTOTAL_API_KEY(self) -> str | None:
        return os.getenv("VIRUSTOTAL_API_KEY")

    @property
    def GOOGLE_SAFE_BROWSING_API_KEY(self) -> str | None:
        return os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    @property
    def URLSCAN_API_KEY(self) -> str | None:
        return os.getenv("URLSCAN_API_KEY")

    @property
    def OTX_API_KEY(self) -> str | None:
        return os.getenv("OTX_API_KEY")

    @property
    def PHISHTANK_API_KEY(self) -> str | None:
        return os.getenv("PHISHTANK_API_KEY")

    @property
    def CLOUDFLARE_API_TOKEN(self) -> str | None:
        return os.getenv("CLOUDFLARE_API_TOKEN")

    @property
    def CLOUDFLARE_ACCOUNT_ID(self) -> str | None:
        return os.getenv("CLOUDFLARE_ACCOUNT_ID")

    @property
    def ANTHROPIC_API_KEY(self) -> str | None:
        return os.getenv("ANTHROPIC_API_KEY")

    # CORS
    @property
    def CORS_ORIGINS(self) -> list[str]:
        return [
            o.strip()
            for o in os.getenv("CORS_ORIGINS", "*").split(",")
            if o.strip()
        ]

    # Module enable flags — True when the relevant key is present
    @property
    def virustotal_enabled(self) -> bool:
        return bool(self.VIRUSTOTAL_API_KEY)

    @property
    def google_safe_browsing_enabled(self) -> bool:
        return bool(self.GOOGLE_SAFE_BROWSING_API_KEY)

    @property
    def urlscan_enabled(self) -> bool:
        return bool(self.URLSCAN_API_KEY)

    @property
    def otx_enabled(self) -> bool:
        return bool(self.OTX_API_KEY)

    @property
    def phishtank_enabled(self) -> bool:
        return bool(self.PHISHTANK_API_KEY)

    @property
    def cloudflare_radar_enabled(self) -> bool:
        return bool(self.CLOUDFLARE_API_TOKEN and self.CLOUDFLARE_ACCOUNT_ID)

    @property
    def anthropic_enabled(self) -> bool:
        return bool(self.ANTHROPIC_API_KEY)

    # Modules that don't need API keys are always enabled
    whois_enabled: bool = True
    ssl_check_enabled: bool = True
    redirect_chain_enabled: bool = True
    keyword_detection_enabled: bool = True
    lookalike_domain_enabled: bool = True
    ip_geolocation_enabled: bool = True
    url_structure_enabled: bool = True
    page_content_enabled: bool = True

    # Email modules (no external keys required)
    header_analysis_enabled: bool = True
    spf_dkim_dmarc_enabled: bool = True
    link_extraction_enabled: bool = True
    content_analysis_enabled: bool = True

    def module_status(self) -> dict:
        return {
            "virustotal": self.virustotal_enabled,
            "google_safe_browsing": self.google_safe_browsing_enabled,
            "urlscan": self.urlscan_enabled,
            "alienvault_otx": self.otx_enabled,
            "phishtank": self.phishtank_enabled,
            "cloudflare_radar": self.cloudflare_radar_enabled,
            "anthropic_ai": self.anthropic_enabled,
            "whois_age": self.whois_enabled,
            "ssl_check": self.ssl_check_enabled,
            "redirect_chain": self.redirect_chain_enabled,
            "keyword_detection": self.keyword_detection_enabled,
            "lookalike_domain": self.lookalike_domain_enabled,
            "ip_geolocation": self.ip_geolocation_enabled,
            "url_structure": self.url_structure_enabled,
            "page_content": self.page_content_enabled,
            "header_analysis": self.header_analysis_enabled,
            "spf_dkim_dmarc": self.spf_dkim_dmarc_enabled,
            "link_extraction": self.link_extraction_enabled,
            "content_analysis": self.content_analysis_enabled,
        }


settings = Settings()
