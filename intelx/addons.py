import re

class IX_Utils:
    @staticmethod
    def verify(sys_id: str) -> bool:
        return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', sys_id.lower())) # Matching for GUID

    @staticmethod
    def verifyURI(url: str) -> bool:
        return bool(re.compile(
            r'^https://'  # Protocol (must be https)
            r'((?!localhost|127\.0\.0\.1)[\w\-\.]+)'  # Domain (bogus host are not allowed)
            r'(\.[a-zA-Z]{2,})'  # TLD (required)
            r'(?:\:\d+)?'  # Port (optional)
            r'(?:/[\w\-./]*)?$'  # Path (optional, can include trailing slashes)
        ).match(url))

    @staticmethod
    def identify(value: str) -> dict | bool:
        for _type, pattern in {
            "email": r"^[\w\.-]+@[\w\.-]+\.\w+$",
            "domain": r"^(www\.)?[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,63}$",
            "url": lambda x: IX_Utils.verifyURI(x),
            "ipv4": r"^(\d{1,3}\.){3}\d{1,3}$",
            "ipv6": r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])$",
            "cidr": r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$",
            "phone": r"^\+\d{1,3}\d{1,14}$",
            "btc": r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
            "eth": r"^0x[a-fA-F0-9]{40}$",
            "mac": r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
            "ipfs": r"^Qm[1-9A-HJ-NP-Za-km-z]{44,}$",
            "ccn": r"^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$",
            "ssn": r"^\d{3}-\d{2}-\d{4}$",
            "iban": r"^[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}$"
        }.items():
            if isinstance(pattern, str) and re.match(pattern, value):
                return {"type": _type}
            elif callable(pattern) and pattern(value):
                return {"type": _type}

        return False
