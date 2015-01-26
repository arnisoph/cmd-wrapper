#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    Cron Usage Examples:

        * cmd-wrapper -t php -r ~/htdocs/jobs.php -p 5.4 1>/dev/null
        * cmd-wrapper -t http -r https://domain.de/jobs.php 1>/dev/null

    TODO:

        * make php bin + ini path configurable
'''

import argparse
import re
import requests
import sys

from subprocess import Popen, PIPE


def exec_php_resource(resource, php_version, script_args=''):
    args = []
    php_version = php_version.replace('.', '')

    php_bin_path = '/usr/bin/php{php_version}/php'.format(php_version=php_version)
    args.append(php_bin_path)

    args.append('-c')
    args.append('~/conf/php{php_version}/'.format(php_version=php_version))

    args.append('-f')
    args.append(resource)

    if script_args:
        for a in script_args.split(' '):
            if a:
                args.append(a)

    p1 = Popen(args, stdout=PIPE)

    return p1.communicate()[0]


def get_http_resource(resource):
    r = requests.get(resource, verify=False)  # TODO disabling that may not be clever

    return r.content


def main():
    version = '0.1'

    php_version_default = '5.5'

    # regex_http = r'^https?://[A-Za-z0-9]+\.[A-Za-z]+[/]+$'
    regex_http = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    regex_file = r'^(/)?([^/\0]+(/)?)+$'
    regex_phpver = r'^5\.[3-6]$'

    parser = argparse.ArgumentParser(description='Command wrapper script for common tasks')

    # General args
    parser.add_argument('-t', action='store', dest='task', help='TASK may be \'php\' or \'http\'', default=None)
    parser.add_argument('-r', action='store', dest='resource', help='RESOURCE may be a file path or http URI', default='')
    parser.add_argument('-v', action='version', version='%(prog)s {version}'.format(version=version))
    parser.add_argument('-a', action='store', dest='script_args', help='space-separated list of script/ program arguments', default='')

    # PHP related args
    parser.add_argument('-p', action='store', dest='php_version', help='PHP_VERSION may be of syntax <MAJOR_VER>.<MINOR_VER>, e.g. 5.6', default=php_version_default)

    # HTTP related args

    results = parser.parse_args()

    resource = results.resource
    task = results.task
    script_args = results.script_args
    php_version = results.php_version

    if task is None:
        print('No task have been defined using -t')
        return 1

    elif task == 'php':
        if not re.match(regex_file, resource):
            print('File resource not given or does not match regex {regex}'.format(regex=regex_http))
            return 1

        if not re.match(regex_phpver, php_version):
            print('PHP version {php_version} does not match regex {regex}'.format(php_version=php_version, regex=regex_phpver))
            return 1

        print(exec_php_resource(resource, php_version, script_args))  # TODO script_args syntax check

    elif task == 'http':
        if not re.match(regex_http, resource):
            print('HTTP resource not given or does not match regex {regex}'.format(regex=regex_http))
            return 1
        print(get_http_resource(resource))

    else:
        print('Unknown task `{task}\''.format(task=resource))
        return 1


if __name__ == "__main__":
    sys.exit(main())