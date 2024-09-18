# Defense

## Server-Side Request Forgery (SSRF)

It's possible to implement proper input validation and sanitation, ensuring that all user-supplied data, including URLs, ate validated and sanitized to prevent malicious input from being processed.

You can also use allowlists for URLs and IP addresses, restricting the range of allowed URLs and IP addresses to minimize the attack surface and prevent unauthorized access to internal resources.

Implementing monitor and log requests is important to detect and investigate potential SSRF attacks in real-time.

## Local File Inclusion (LCI)

To prevent it, developers can use input validation and sanitization and use of absolute paths.

It's possible to use ID assignation to the files. Saving files paths in a secure database and give an ID for every single one, this way users only get to see their ID without viewing or altering the path.

It's also possible to use whitelisting files and ignore everything else.

Using databases instead of files is a common way to mitigate LFI.

