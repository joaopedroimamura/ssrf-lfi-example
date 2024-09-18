# Server-Side Request Forgery (SSRF)

This application has a SSRF vulnerability. It's possible to read server files content.

## What is Server-Side Request Forgery (SSRF)?

Server-Side Request Forgery is a web security vulnerability that allows an attacker to cause the server-side application to make requests to an unintended location.

In a typical SSRF attack, the attacker might cause the server to make a connection to internal-only services within the organization's infrastructure. In other cases, they may be able to force the server to connect to arbitrary external systems. This could leak sensitive data, such as authorization credentials.

SSRF is not limited to the HTTP protocol. Generally, the first request is HTTP, but in cases where the application itself performs the second request, it could use different protocols (e.g. FTP, SMB, SMTP, etc.) and schemes (e.g. ```file://```, ```phar://```, ```gopher://```, ```data://```, ```dict://```, etc.).

## Impact

A successful SSRF attack can often result in unauthorized actions or access to data within the organization. This can be in the vulnerable application, or on other back-end systems that the application can communicate with. In some situations, the SSRF vulnerability might allow an attacker to perform arbitrary command execution.

An SSRF exploit that causes connections to external third-party systems might result in malicious onward attacks. These can appear to originate from the organization hosting the vulnerable application.

## Common attacks

SSRF attacks often exploit trust relationships to escalate an attack from the vulnerable application and perform unauthorized actions. These trust relationships might exist in relation to the server, or in relation to other back-end systems within the same organization.

### SSRF attacks against the server

In this type of attack, the attacker causes the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface. This typically involves supplying a URL with a hostname like ```127.0.0.1``` (a reserved IP address that points to the loopback adapter) or ```localhost``` (a commonly used name for the same adapter).

Imagine a shopping application that lets the user view whether an item is in stock in a particular store.

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

It's possible to modify the request to specify a URL local to the server:

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://localhost/admin
```

Now, the request for ```/admin``` comes from the local machine and the normal access controls are bypassed. The application grants full access to the administrative functionality, because the request appears to originate from a trusted location.

Applications implicitly trust requests that come from the local machine.

- The access control check might be implemented in a different component that sits in front of the application server. When a connection is made back to the server, the check is bypassed.

- For disaster recovery purposes, the application might allow administrative access without logging in, to any user coming from the local machine. This provides a way for an administrator to recover the system if they lose their credentials. This assumes that only a fully trusted user would come directly from the server.

- The administrative interface might listen on a different port number to the main application, and might not be reachable directly by users.

### SSRF attacks against other back-end systems

In some cases, the application server is able to interact with back-end systems that are not directly reachable by users. These systems often have non-routable private IP addresses. The back-end systems are normally protected by the network topology, so they often have a weaker security posture. In many cases, internal back-end systems contain sensitive functionality that can be accessed without authentication by anyone who is able to interact with the systems.

Imagine an administrative interface at ```https://192.168.0.68/admin```.

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://192.168.0.68/admin
```

## Circumventing common SSRF defenses

It's common to see applications containing SSRF behavior together with defenses aimed at preventing malicious exploitation. Often, these defenses can be circumvented.

### SSRF with blacklist-based input filters

Some applications block input containing hostnames like ```127.0.0.1``` and ```localhost```, or sensitive URLs like ```/admin```. In this situation, you can often circumvent the filter using the following techniques:

- Use an alternative IP representation of ```127.0.0.1```, such as ```2130706433```, ```017700000001```, or ```127.1```.

- Register your own domain name that resolves to ```127.0.0.1```. 

- Obfuscate blocked strings using URL encoding or case variation.

- Provide a URL that you control, which redirects to the target URL. Try using different redirect codes, as well as different protocols for the target URL. For example, switching from ```http:``` to ```https:``` URL during the redirect has been shown to bypass some anti-SSRF filters.

### SSRF with whitelist-based input filters

Some applications only allow inputs that match a whitelist of permitted values. The filter may look for a match at the beggining of the input, or contained within in it. You may be able to bypass this filter by exploiting inconsistencies in URL parsing.

The URL specification contains a number of features that are likely to be overlooked when URLs implement ad-hoc parsing and validation using this method:

- You can embed credentials in a URL before the hostname, using the ```@``` character. For example: ```https://expected-host:fakepassword@evil-host```

- You can use the ```#``` character to indicate a URL fragment. For example: ```https://evil-host#expected-host```.

- You can leverage the DNS naming hierarchy to place required input into a fully-qualified DNS name that you control. For example: ```https://expected-host.evil-host```.

- You can URL-encode characters to confuse the URL-parsing code. This is particularly useful if the code that implements the filter handles URL-encoded characters differently than the code that performs the back-end HTTP request. You can also try double-encoding characters, some servers recursively URL-decode the input they receive, which can lead to further discrepancies.

- You can use combinations of these techniques together.

### Bypassing SSRF filters via open redirection

It is sometimes possible to bypass filter-based defenses by exploiting an open redirection vulnerability.

Imagine the user-submitted URL is strictly validated to prevent malicious exploitation of the SSRF behavior. However, the application whose URLs are allowed contains an open redirection vulnerability. Provided the API used to make the back-end HTTP request supports redirections, you can construct a URL that satisfies the filter and results in a redirected request to the desired back-end target.

For example, the application contains an open redirection vulnerability in which the URL ```/product/nextProduct?currentProductId=6&path=http://evil-user.net``` returns a redirection to: ```http://evil-user.net```. It's possible to leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:

```
POST /product/stock HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 118

stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

This SSRF exploit works because the application first validates that the supplied ```stockApi``` URL is on an allowed domain, which it is. The application then requests the supplied URL, which triggers the open redirection. It follows the redirection, and makes a request to the internal URL of the attacker's choosing.

## Blind SSRF vulnerabilities

Blind SSRF vulnerabilities occur if you can cause an application to issue a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the applications' front-end response.

Blind SSRF is harder to exploit but sometimes leads to full remote code execution on the server or other back-end components.

### How to find and exploit

The most reliable way to detect blind SSRF vulnerabilities is using out-of-band (OAST) techniques. This involves attempting to trigger an HTTP request to an external system that you control, and monitoring for network interactions with that system.

It's possible to generate unique domain names, send these in payloads to the application, and monitor for any interaction with those domains. If an incoming HTTP request is observed coming from the applciation, then it is vulnerable to SSRF.

Since it's not possible to view the response from the back-end request, the behavior can't be used to explore content on systems that the application server can reach. However, it can still be leveraged to probe for other vulnerabilities on the server itself or on other back-end systems. You can blindly sweep the internal IP address space, sending payloads designed to detect well-known vulnerabilities. If those payloads also employ blind out-of-band techniques, then you might uncover a critical vulnerability on an unpatched internal server.

Another avenue for exploiting blind SSRF vulnerabilities is to induce the application to connect to a system under the attacker's control, and return malicious responses to the HTTP client that makes the connection. If you can exploit a serious client-side vulnerability in the server's HTTP implementation, you might be able to achieve remote code execution within the application infrastructure.

## Finding hidden attack surface for SSRF vulnerabilities

Many server-side request forgery vulnerabilities are easy to find, because the application's normal traffic involves request parameters containing full URLs.

### Partial URLs in requests

Sometimes, an application places only a hostname or part of a URL path into request parameters. The value submitted is then incorporated server-side into a full URL that is requested. If the value is readily recognized as a hostname or URL path, the potential attack surface might be obvious. However, exploitability as full SSRF might be limited because you do not control the entire URL that gets requested.

### URLs within data formats

Some applications transmit data in formats with a specification that allows the inclusion of URLs that might get requested by the data parser for the format. An obvious example of this is the XML data format, which has been widely used in web applications to transmit structured data from the client to the server. When an application accepts data in XML format and parses it, it might be vulnerable to XXE injection. It might also be vulnerable to SSRF via XXE.

### SSRF via the Referer header

Some applications use server-side analytics software to tracks visitors. This software often logs the Referer header in requests, so it can track incoming links. Often the analytics software visits any third-party URLs that appear in the Referer header. This is typically done to analyze the contents of referring sites, including the anchor text that is used in the incoming links. As a result, the Referer header is often a useful attack surface for SSRF vulnerabilities.

# Local File Inclusion (LFI)

This application has a LFI vulnerability. It's possible to read server files content.

## What is Local File Inclusion (LFI)?

Local File Inclusion is an attack technique in which attackers trick a web application into either running or exposing files on a web server. LFI attacks can expose sensitive information, and in severe cases, they can lead to Cross-Site Scripting (XSS) and remote code execution.

For example, if the application uses code like this, which includes the name of a file in the URL:

```https://example-site.com/?module=contact.php```

An attacker can change the URL to look like this:

```https://example-site.com/?module=/etc/passwd```

And in the absence of proper filtering, the server will display the sensitive content of the /etc/passwd file.

## How it works?

When an application uses a file path as an input, the app treats that input as trusted and safe. A local file can then be injected into the included statement. This happens when the code is vulnerable. In some cases, if the application provides the ability to upload files, attackers can run any server-side malicious code they want. 

## Impacts

Information disclosure can reveal important information about the application and its configuration. That information can be valuable to an attacker to gain a deepdr understanding of the application and can help them detect and exploit other vulnerabilities.

It's also possible to lead to Directory Traversal attacks, where an attacker will try to find and access files on the web server to gain  more useful information, such as log files that reveal the structure of the application or expose paths to sensitive files.

Combined with a file upload vulnerability, a LFI vulnerability can lead to remote code execution. In this case the attacker would use LFI to executed the unwanted file. To compound matters, an attacker can upload a file to the server to gain the ability to execute commands remotely, resulting in the attacker being able to control the whole server remotely.

## Scenarios where LFI are used

### Including files to be parsed by the language's interpreter

A URL like this ```https://example-site.com/?module=contact.php``` can be changed to ```https://example-site.com/?module=/etc/passwd```.

### Including files that are served as downloads

There is types of files that all web browsers automatically open (PDF, for example). Users can configure this so the files get downloaded instead of shown in the browser window. That's achieved by adding an additional header that tells the browser to do things differently. A simple ```Content-Disposition: attachment; filename=file.pdf``` addition in the request and now the files are downloaded instead of opened. An example would look something like this ```https://example-site.com/?download=brochure.pdf```. An issue arises when the request isn't sanitized. This way the hacker has the option of requesting the download of the base files and read the source code and find other web application vulnerabilities.

## Manually testing

### Basic payloads

Start by injecting simple payloads to see if the application is vulnerable. Common payloads include:

- ```../../etc/passwd```

### Null Byte Injection

The terms "null character", "null terminator", and "null byte" all refer to a control character where the value zero is present in the reserved character sets used to mark the end of the string. The null byte ensures that any character following it is ignored. Typically, a null byte is injected as %00 at the ond of a URL. ```https://example-site.com/preview.php?file=../../../../../passwd%00```

### Encoding

Test URL encoding to bypass filters:

- %2e%2e%2f (encoded ```../```)
- %c0%ae%c0%ae%2f (double encoded ```../```)

### Error Messages

Check for error messages that may reveal file paths or directory structures. For example, including a non-existent file might return a stack trace.

