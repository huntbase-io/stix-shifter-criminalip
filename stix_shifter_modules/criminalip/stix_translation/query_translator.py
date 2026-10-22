import logging

from stix_shifter_utils.modules.base.stix_translation.base_query_translator import BaseQueryTranslator
from . import query_constructor

logger = logging.getLogger(__name__)


class QueryTranslator(BaseQueryTranslator):

    def transform_antlr(self, data, antlr_parsing_object):
        """
        Transforms a STIX pattern into one or more Criminal IP banner search queries.
        :param data: STIX pattern
        :param antlr_parsing_object: Antlr parsing objects for the STIX pattern
        :return: list of query strings (see query_constructor for the format)
        """
        logger.info("Converting STIX2 Pattern to data source query")
        return query_constructor.translate_pattern(antlr_parsing_object, self, self.options)
