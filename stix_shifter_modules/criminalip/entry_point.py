from stix_shifter_utils.utils.base_entry_point import BaseEntryPoint
from .stix_translation.criminalip_query_translator import CriminalIPQueryTranslator, LANGUAGE


class EntryPoint(BaseEntryPoint):
    # STIX:   python main.py translate criminalip query '{}' "[ipv4-addr:value = '8.8.8.0/24']"
    # native: python main.py translate criminalip query '{}' "product: OpenSSH port: 22" '{"language":"criminalip"}'

    def __init__(self, connection={}, configuration={}, options={}):
        super().__init__(connection, configuration, options)
        self.set_async(False)
        if connection:
            self.setup_transmission_basic(connection, configuration)
        self.setup_translation_simple(dialect_default='default')
        # Native Criminal IP query passthrough, selected with the {"language": "criminalip"} option.
        self.add_dialect(LANGUAGE, CriminalIPQueryTranslator(options, LANGUAGE, None), default_include=True,
                         default=True)
