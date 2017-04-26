#!/usr/bin/env python

import dns.resolver
import itertools 
import argparse
import sys

def bruteforce(charset, minlength, maxlength):
    return (''.join(candidate)
        for candidate in itertools.chain.from_iterable(itertools.product(charset, repeat=i)
        for i in range(minlength, maxlength + 1)))



def update_tld():
	''' a function to update the TLD list from https://www.icann.org/resources/pages/tlds-2012-02-25-en '''
	pass


def domain_generate():
	''' a function to generate domain with provided strings and TLDs. '''
	pass


def main(args):
	charset = 'abcdefghijklmnopqrstuvwxyz'
	records = {'a':'A', 'aaaa':'AAAA', 'ns':'NS', 'ptr':'PTR', 'mx':'MX', 'srv':'SRV', 'txt':'TXT', 'soa':'SOA', 'spf':'SPF'}
	# tlds = ()
	domain, tld = args.domain.split(".")

	myResolver = dns.resolver.Resolver() 

	for gen in list(bruteforce(charset, args.min, args.max)):
		fqdn = domain + gen + '.' + tld
		if args.record is None:
			for idx in records.values():
				try:
					myAnswer = myResolver.query(fqdn, idx)
					for rdata in myAnswer: 
						print("[+] Query {} for {} record: {}".format(fqdn, idx, rdata))
				except (KeyboardInterrupt, SystemExit):
					print("Keyboard interrupt detected. Quitting...")
					sys.exit(0)
				except:
					print("[-] Query {} for {} record: NO RECORDS".format(fqdn, idx))
		else:
			try:
				myAnswer = myResolver.query(fqdn, args.record)
				for rdata in myAnswer: 
					print("[+] Query {} for {} record: {}".format(fqdn, args.record, rdata))
			except (KeyboardInterrupt, SystemExit):
				print("Keyboard interrupt detected. Quitting...")
				sys.exit(0)
			except:
				print("[-] Query {} for {} record: NO RECORDS".format(fqdn, args.record))


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--domain', required=True)
	parser.add_argument('-r', '--record', help='Domain record to find. \
						Available options: A, AAAA, NS, PTR, MX, SRV, TXT, SOA, SPF. \
						If no argument given - print all of them.')
	parser.add_argument('--min', default=0, required=False, help='Minimal string length.')
	parser.add_argument('--max', default=0, required=False, help='Maximal string length.')
	parser.add_argument('-t', '--tld', required=False, help='Top Level Domain. Available options - update, all, known, selected.')
	parser.add_argument('-p', '--print', required=False, help='Print only found records.') 	
	parser.add_argument('-f', '--file', required=False, help='Save output to a file.')
	args = parser.parse_args()
	main(args)

