#!/usr/bin/env python3

# Email Security Check Tool
# Creator: Kairat Amanzharov
# Inspired by: Kirill Murzin
# PACIFICA LLP Summer Practice 2018

from subprocess import Popen, PIPE
from platform import system
from sys import exit
import smtplib

ports = [25, 587]
system_platform = system()

if system_platform == 'Windows':
	def mx_format(domain):
		return 'nslookup -type=mx %s 8.8.8.8' % domain
	def spf_format(domain):
		return 'nslookup -type=txt %s 8.8.8.8' % domain
	def dmarc_format(domain):
		return 'nslookup -type=txt %s 8.8.8.8' % ('_dmarc.' + domain)
elif system_platform == 'Linux':
	def mx_format(domain):
		return 'host -t mx %s 8.8.8.8' % domain
	def spf_format(domain):
		return 'host -t txt %s 8.8.8.8' % domain
	def dmarc_format(domain):
		return 'host -t txt %s 8.8.8.8' % ('_dmarc.' + domain)
else:
	exit('Your platform is not supported.')

def find_dmarc(domain):
	out = []
	process = execute(dmarc_format(domain))
	if system_platform == 'Linux':
		if 'not found' in process[0] or 'no TXT' in process[0]:
			print(process[0])
			return ''
		for record in process[0].split('\n'):
			if 'DMARC' in record:
				for x in record.split('"'):
					if 'DMARC' in x:
						out += [x.strip()]
		if len(out) == 0:
			print('No DMARC records found')
			return ''
	elif system_platform == 'Windows':
		for record in process[0].split('\n'):
			if 'DMARC' in record:
				out += [record.strip()]
		if len(out) == 0:
			print('No DMARC records found')
			return ''
	return out

def find_spf(domain):
	out = []
	process = execute(spf_format(domain))
	if system_platform == 'Linux':
		if 'not found' in process[0]:
			print(process[0])
			return ''
		for record in process[0].split('\n'):
			if 'spf' in record:
				for x in record.split('"'):
					if 'spf' in x:
						out += [x.strip()]
		if len(out) == 0:
			print('No spf records found')
			return ''
	elif system_platform == 'Windows':
		for record in process[0].split('\n'):
			if 'spf' in record:
				out += [record.strip()]
		if len(out) == 0:
			print('No spf records found')
			return ''
	return out

def find_mx(domain):
	mx_hosts = []
	process = execute(mx_format(domain))
	if system_platform == 'Linux':
		if 'no MX record' in process[0] or 'not found' in process[0]:
			print(process[0])
			return ''
		for record in process[0].split('\n'):
			if 'mail is handled' in record:
				mx_hosts += [record.split()[-1][:-1]]
		return mx_hosts
	elif system_platform == 'Windows':
		for record in process[0].split('\n'):
			if 'mail exchanger' in record:
				mx_hosts += [record.split()[-1]]
		if len(mx_hosts) == 0:
			print('Can not find mx record!')
			return ''
		return mx_hosts

def execute(command):
	process = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
	process.wait()
	out, err = process.communicate()
	out = out.decode('utf-8', errors='ignore')
	err = err.decode('utf-8', errors='ignore')
	return [out, err]

def show_spf():
	address = input('Type a domain to check SPF record\n> ')
	result = find_spf(address)
	if result == '':
		return
	print('\n'.join(result))
	return

def show_dmarc():
	address = input('Type a domain to check DMARC record\n> ')
	result = find_dmarc(address)
	if result == '':
		return
	print('\n'.join(result))
	return

def spf():
	tls = False
	recipient_address = ''
	while True:
		recipient_address = input('Type a recipient address\n> ')
		if '@' not in recipient_address:
			print('Type a correct address!')
			continue
		proceed = input('Send message ?\n1 - Yes\n2 - Configure\n3 - Exit to menu\n> ')
		if proceed == '1':
			break
		elif proceed == '2':
			continue
		else:
			return
	domain = recipient_address.split('@')[1]
	mx_records = find_mx(domain)
	if mx_records == '':
		return
	while True:
		for mx in mx_records:
			status = False
			gotConnection = False
			for port in ports:
				print('Trying {} on port {}'.format(mx, port))
				try:
					smtp = smtplib.SMTP(mx, port, domain)
					gotConnection = True
				except smtplib.SMTPConnectError:
					print('Can not connect to {} on port {}'.format(mx, port))
					continue
				except Exception as ex:
					print(ex)
					return
				try:
					smtp.ehlo()
					if tls:
						smtp.starttls()
						smtp.ehlo()
					smtp.sendmail(recipient_address, recipient_address, 'Subject: No SPF Exist\n\nSPF test message.')
					smtp.quit()
					status = True
					break
				except smtplib.SMTPSenderRefused as exception:
					out = []
					for ex in exception.args[:]:
						if type(ex) == bytes:
							ex = ex.decode('utf-8', errors='ignore')
						if type(ex) == str:
							if 'STARTTLS' in ex:
								tls = True
						out += [str(ex)]
					print(' '.join(out))
					if tls:
						print('TLS will be turned on if you press retry.')
					break
				except smtplib.SMTPRecipientsRefused as exception:
					out = []
					for ex in exception.args[0][recipient_address]:
						if type(ex) == bytes:
							ex = ex.decode('utf-8', errors='ignore')
						out += [str(ex)]
					print(' '.join(out))
					break
				except smtplib.SMTPDataError as exception:
					out = []
					for ex in exception.args[:]:
						if type(ex) == bytes:
							ex = ex.decode('utf-8', errors='ignore')
						out += [str(ex)]
					print(' '.join(out))
					break
				except Exception as ex:
					print(ex)
					print(type(ex))
					return
			if status:
				print('Message sent successfully!')
				break
			if gotConnection:
				break
		repeat = input('1 - Retry\n2 - Configure\n3 - Exit to menu\n> ')
		if repeat == '1':
			continue
		elif repeat == '2':
			break
		else:
			return
	spf()
	return

def dmarc():
	tls = False
	sender_address = ''
	recipient_address = ''
	while True:
		recipient_address = input('Type a recipient address\n> ')
		if '@' not in recipient_address:
			print('Type a correct address!')
			continue
		while True:
			sender_address = input('Type a sender address with correct spf record (~all or +all)\n> ')
			if '@' not in sender_address:
				print('Type a correct address!')
				continue
			else:
				break
		proceed = input('Send message ?\n1 - Yes\n2 - Configure\n3 - Exit to menu\n> ')
		if proceed == '1':
			break
		elif proceed == '2':
			continue
		elif proceed == '3':
			return
	domain = recipient_address.split('@')[1]
	mx_records = find_mx(domain)
	if mx_records == '':
		return
	while True:
		for mx in mx_records:
			status = False
			gotConnection = False
			for port in ports:
				print('Trying {} on port {}'.format(mx, port))
				try:
					smtp = smtplib.SMTP(mx, port, sender_address.split('@')[1])
					gotConnection = True
				except smtplib.SMTPConnectError:
					print('Can not connect to {} on port {}'.format(mx, port))
					continue
				except Exception as ex:
					print(ex)
					return
				try:
					smtp.ehlo()
					if tls:
						smtp.starttls()
						smtp.ehlo()
					smtp.sendmail(sender_address, recipient_address, 'From: Security Team <{}>\nTo: User <{}>\nSubject: No DMARC Exist\n\nDmarc test.'.format('security@' + domain, recipient_address))
					smtp.quit()
					status = True
					break
				except smtplib.SMTPSenderRefused as exception:
					out = []
					for ex in exception.args[:]:
						if type(ex) == bytes:
							ex = ex.decode('utf-8', errors='ignore')
						if type(ex) == str:
							if 'STARTTLS' in ex:
								tls = True
						out += [str(ex)]
					print(' '.join(out))
					if tls:
						print('TLS will be turned on if you press retry.')
					break
				except smtplib.SMTPRecipientsRefused as exception:
					out = []
					for ex in exception.args[0][recipient_address]:
						if type(ex) == bytes:
							ex = ex.decode('utf-8', errors='ignore')
						out += [str(ex)]
					print(' '.join(out))
					break
				except smtplib.SMTPDataError as exception:
					out = []
					for ex in exception.args[:]:
						if type(ex) == bytes:
							ex = ex.decode('utf-8', errors='ignore')
						out += [str(ex)]
					print(' '.join(out))
					break
				except Exception as ex:
					print(ex)
					print(type(ex))
					return
			if status:
				print('Message sent successfully!')
				break
			if gotConnection:
				break
		repeat = input('1 - Retry\n2 - Configure\n3 - Exit to menu\n> ')
		if repeat == '1':
			continue
		elif repeat == '2':
			break
		else:
			return
	dmarc()
	return

while True:
	technique = input('1 - Show SPF\n2 - Show DMARC\n3 - SPF Test\n4 - DMARC Test\n5 - Exit\n> ')
	if technique == '1':
		show_spf()
	elif technique == '2':
		show_dmarc()
	elif technique == '3':
		spf()
	elif technique == '4':
		dmarc()
	elif technique == '5':
		break
