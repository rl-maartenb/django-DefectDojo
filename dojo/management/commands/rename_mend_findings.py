import logging
import re

from django.core.management.base import BaseCommand
from pytz import timezone

from dojo.celery import app
from dojo.models import Finding, Test_Type
from dojo.utils import get_system_setting

logger = logging.getLogger(__name__)

locale = timezone(get_system_setting("time_zone"))

"""
Author: Aaron Weaver
This script will update the hashcode and dedupe findings in DefectDojo:
"""


class Command(BaseCommand):
    help = "No input commands for dedupe findings."

    def handle(self, *args, **options):
        rename_mend_finding()


@app.task(name="rename_mend_finding_task")
def rename_mend_finding():
    mend_id = Test_Type.objects.get(name="Mend Scan").id
    findings = Finding.objects.filter(found_by=mend_id)
    findings = findings.order_by("-pk")
    logger.info("######## Updating Hashcodes - deduplication is done in the background upon finding save ########")
    for finding in findings:
        logger.info("Updating Mend Finding with id: %d", finding.id)
        lib_name_begin = re.search(r"\*\*Library Filename\*\* : ", finding.description).span(0)[1]
        lib_name_end = re.search(r"\*\*Library Description\*\*", finding.description).span(0)[0]
        lib_name = finding.description[lib_name_begin:lib_name_end - 1]
        if finding.cve is None:
            finding.title = "CVE-None | " + lib_name
        else:
            finding.title = finding.cve + " | " + lib_name
        if not finding.cwe:
            logger.debug("Set cwe for finding %d to 1035 if not an cwe Number is set", finding.id)
            finding.cwe = 1035
        finding.title = finding.title.rstrip()  # delete \n at the end of the title
        finding.hash_code = finding.compute_hash_code()
        finding.save()
