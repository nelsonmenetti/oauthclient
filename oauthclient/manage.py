#!/usr/bin/env python
import os
import sys
import logging.config

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "oauthclient.settings")

    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
    logging.config.fileConfig("oauthclient/logging", defaults=None, disable_existing_loggers=False)
