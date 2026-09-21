import re
from typing import Any, Dict
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
from .base import BaseModule


class PhoneHlrModule(BaseModule):
    module_id = "phone_hlr"
    name = "Phone HLR"
    tag = "TEL"
    input_placeholder = "Enter phone with country code (e.g. +14155552671, +79991234567)..."
    description = "HLR lookup, carrier identification, line type & geolocation"

    def validate_target(self, target: str) -> tuple[bool, str]:
        cleaned = re.sub(r"[\s\-\(\)]", "", target.strip())
        if not cleaned.startswith("+"):
            cleaned = "+" + cleaned

        try:
            parsed = phonenumbers.parse(cleaned, None)
            if not phonenumbers.is_possible_number(parsed):
                return False, "Number format is invalid or impossible"
            return True, ""
        except phonenumbers.NumberParseException as exc:
            return False, f"Invalid phone format: {str(exc)}"

    async def run(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        cleaned = re.sub(r"[\s\-\(\)]", "", target.strip())
        if not cleaned.startswith("+"):
            cleaned = "+" + cleaned

        parsed = phonenumbers.parse(cleaned, None)
        is_valid = phonenumbers.is_valid_number(parsed)

        # 1. Определение типа линии
        num_type_code = phonenumbers.number_type(parsed)
        type_mapping = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Landline (Fixed)",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed or Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "Universal Access",
            phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
            phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
        }
        line_type = type_mapping.get(num_type_code, "Unknown")

        # 2. Определение оператора и региона
        carrier_name = carrier.name_for_number(parsed, "en") or "Independent / Virtual"
        region_geo = geocoder.description_for_number(parsed, "en") or "N/A"
        timezones = timezone.time_zones_for_number(parsed)
        tz_str = ", ".join(timezones) if timezones else "N/A"

        # Форматы номера
        e164_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat_format = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

        raw_payload = {
            "query": target,
            "valid": is_valid,
            "e164": e164_format,
            "international": intl_format,
            "national": nat_format,
            "country_code": parsed.country_code,
            "national_number": str(parsed.national_number),
            "carrier": carrier_name,
            "line_type": line_type,
            "location": region_geo,
            "timezones": list(timezones),
        }

        return {
            "metrics": {
                "Phone Number": intl_format,
                "Carrier / Telecom": carrier_name,
                "Line Type": line_type,
                "Geo Location": region_geo,
            },
            "raw": raw_payload,
        }
