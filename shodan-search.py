#!/usr/bin/env python2

import shodan
import argparse

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-a", "--apikey", help="Your api key")
   parser.add_argument("-s", "--search", help="Your search terms")
   return parser.parse_args()

def shodan_search(search, apikey):

    if apikey:
        API_KEY = apikey
    else:
        API_KEY = 'REPLACE WITH API KEY AND KEEP QUOTES'

    api = shodan.Shodan(API_KEY)
    ips_and_ports = []

    # Get IPs from Shodan search results
    try:
        results = api.search(search, page=1)
        total_results = results['total']
        print '[+] Total results: {0}'.format(total_results)
        print '[+] First page:'
        for r in results['matches']:
            ip = r['ip_str']
            port = r['port']
            ip_port = '{0}:{1}'.format(ip, port)
            print '    ', ip_port

    except Exception as e:
        print '[!] Shodan search error:', e

def main():
    args = parse_args()
    apikey = args.apikey
    search = args.search
    shodan_search(search, apikey)

main()
