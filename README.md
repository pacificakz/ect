Email Security Check Tool is a tool that will help you to test your mail configuration, specifically SPF and DMARC.

Definitions:
	Sender Policy Framework (SPF) is an email validation protocol designed to detect and block email spoofing by providing a mechanism to allow receiving mail exchangers to verify that incoming mail from a domain comes from an IP Address authorized by that domain's administrators.
	Domain-based Message Authentication, Reporting and Conformance (DMARC) is an email-validation system designed to detect and prevent email spoofing. It is intended to combat certain techniques often used in phishing and email spam, such as emails with forged sender addresses that appear to originate from legitimate organizations.

Supported platforms:
	Linux
	Windows

ECT has four options:
1) Show SPF
2) Show DMARC
3) SPF Test
4) DMARC Test

ECT automatically finds mx records for desired domain
Example:
	Linux -> host -t mx example.com 8.8.8.8
	Windows -> nslookup -type=mx example.com 8.8.8.8

How to use:

	Show SPF:
	"Type a domain to check SPF record" - type a domain which you would like to check for SPF record
	Example:
		example.com
		Output -> "v=spf1 a mx ~all"

	Show DMARC:
	"Type a domain to check DMARC record" - type a domain which you would like to check for DMARC record
	Example:
		example.com
		Output -> "v=DMARC1; p=none"

	SPF Test:
	"Type a recipient address" - type a user and domain which will be a recipient
	Example:
		user@example.com
	"Send message ?" - you can send message, reconfigure your recipient address or exit to menu
	ECT will try to send message to mail server
	If message sent without errors, you will see "Message sent successfully", otherwise you see error message
	If "530 5.7.0 Must issue a STARTTLS command first user@example.com" appeared, just press retry, ECT will turn it on next turn
	In the end you will be asked for retry, reconfigure or exit to menu

	DMARC Test:
	"Type a recipient address" - type a user and domain which will be a recipient
	Example:
		user@example.com
	"Type a sender address with correct spf record (~all or +all)" - type a user and domain which will be a sender
	Example:
		attacker@evil.com
	"Send message ?" - you can send message, reconfigure your recipient address or exit to menu
	ECT will try to send message to mail server
	If message sent without errors, you will see "Message sent successfully", otherwise you see error message
	If "530 5.7.0 Must issue a STARTTLS command first user@example.com" appeared, just press retry, ECT will turn it on next turn
	In the end you will be asked for retry, reconfigure or exit to menu
