// Generic vulnerability descriptions for common vulnerability types
// Used when Nuclei template descriptions are missing or need enhancement

export const VULN_DESCRIPTIONS = {
  // XSS - Cross-Site Scripting
  'xss': {
    title: 'Cross-Site Scripting (XSS)',
    description: 'Cross-Site Scripting (XSS) attacks are a type of injection attack where malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.',
    impact: 'Attackers can execute scripts in the victim\'s browser which can hijack user sessions, deface websites, redirect users to malicious sites, or steal sensitive information including session cookies and credentials.',
    remediation: 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Sanitize all user inputs and use context-aware output encoding.'
  },

  // LFI - Local File Inclusion
  'lfi': {
    title: 'Local File Inclusion (LFI)',
    description: 'Local File Inclusion (LFI) is an attack technique where attackers trick a web application into including files that already exist on the server. This typically occurs when user input is passed to file include functions without proper validation.',
    impact: 'Successful LFI attacks can lead to information disclosure (reading sensitive files like /etc/passwd, configuration files, source code), remote code execution if combined with file upload, and complete system compromise.',
    remediation: 'Avoid passing user-supplied input to filesystem/framework file operations. Implement a whitelist of allowed files. Use absolute paths and avoid directory traversal patterns. Apply proper input validation and sanitization.'
  },

  // RFI - Remote File Inclusion
  'rfi': {
    title: 'Remote File Inclusion (RFI)',
    description: 'Remote File Inclusion (RFI) is a vulnerability that allows an attacker to include a remote file, usually through a script on the web server. This occurs when user input is improperly validated and used to load files from external sources.',
    impact: 'RFI can lead to remote code execution, data theft, website defacement, and complete server compromise as attackers can inject and execute malicious code from external sources.',
    remediation: 'Disable allow_url_include in PHP. Validate and sanitize all user inputs. Use whitelists for file operations. Implement proper access controls and firewall rules.'
  },

  // SQL Injection
  'sqli': {
    title: 'SQL Injection',
    description: 'SQL Injection is a code injection technique that exploits security vulnerabilities in database layer of applications. Attackers can insert malicious SQL statements into application queries, allowing them to manipulate the database.',
    impact: 'Successful SQL injection can result in unauthorized access to sensitive data, data modification or deletion, administrative access to databases, and in some cases, command execution on the operating system.',
    remediation: 'Use parameterized queries (prepared statements). Employ ORM frameworks. Validate and sanitize all user inputs. Apply principle of least privilege for database accounts. Use Web Application Firewalls (WAF).'
  },

  // SSRF - Server-Side Request Forgery
  'ssrf': {
    title: 'Server-Side Request Forgery (SSRF)',
    description: 'Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to make requests from the vulnerable server to arbitrary destinations. The attacker can abuse the server\'s functionality to access internal resources or external services.',
    impact: 'SSRF can lead to internal network scanning, access to cloud metadata services (AWS, Azure, GCP), bypass of firewall rules, exposure of internal services, and potential remote code execution.',
    remediation: 'Implement URL whitelisting. Validate and sanitize user-supplied URLs. Disable unused URL schemas. Use network segmentation. Implement egress filtering.'
  },

  // Open Redirect
  'open-redirect': {
    title: 'Open Redirect',
    description: 'An Open Redirect vulnerability occurs when a web application accepts a user-controlled input that specifies a link to an external site and uses that link in a redirect without proper validation.',
    impact: 'Attackers can craft malicious URLs that appear legitimate, leading to phishing attacks, malware distribution, and credential theft. Victims may be redirected to attacker-controlled sites believing they\'re accessing trusted domains.',
    remediation: 'Avoid redirecting users to URLs from untrusted sources. Implement a whitelist of approved redirect destinations. Use indirect references (like IDs) instead of full URLs. Validate all redirect parameters.'
  },

  // CORS Misconfiguration
  'cors': {
    title: 'CORS Misconfiguration',
    description: 'Cross-Origin Resource Sharing (CORS) misconfiguration occurs when a web application improperly configures CORS headers, allowing unauthorized domains to access sensitive resources or functionality.',
    impact: 'Attackers can steal sensitive data, perform unauthorized actions on behalf of users, bypass Same-Origin Policy protections, and potentially gain access to internal APIs and services.',
    remediation: 'Avoid using wildcard (*) for Access-Control-Allow-Origin. Whitelist specific trusted domains. Properly validate Origin headers. Avoid reflecting the Origin header without validation.'
  },

  // CVE - Common Vulnerabilities and Exposures
  'cve': {
    title: 'Known CVE Vulnerability',
    description: 'A Common Vulnerabilities and Exposures (CVE) is a publicly disclosed security vulnerability that has been assigned a unique identifier. These vulnerabilities have known exploits and documented impacts.',
    impact: 'Impact varies by specific CVE but can include remote code execution, privilege escalation, information disclosure, denial of service, and complete system compromise.',
    remediation: 'Update affected software to the latest patched version. Apply vendor security patches immediately. If patches are unavailable, implement compensating controls or consider alternative solutions.'
  },

  // Outdated Software
  'outdated-software': {
    title: 'Outdated / End-of-Life Software',
    description: 'Running outdated or end-of-life (EOL) software means using versions that are no longer supported by vendors and no longer receive security updates. This leaves systems vulnerable to known exploits.',
    impact: 'Outdated software contains known vulnerabilities that attackers can easily exploit. This can lead to data breaches, system compromise, compliance violations, and increased attack surface.',
    remediation: 'Update to the latest supported version immediately. Plan regular update cycles. Subscribe to security advisories. Implement vulnerability scanning to detect outdated components.'
  },

  // Default Credentials
  'default-login': {
    title: 'Default or Weak Credentials',
    description: 'Systems or applications configured with default, weak, or commonly used credentials that can be easily guessed or found in documentation, making unauthorized access trivial for attackers.',
    impact: 'Attackers can gain unauthorized access to administrative interfaces, sensitive data, and critical systems. This often leads to complete system compromise, data theft, and lateral movement within networks.',
    remediation: 'Change all default credentials immediately. Enforce strong password policies. Implement multi-factor authentication. Use unique passwords for each system. Regularly audit accounts and access.'
  },

  // Exposure
  'exposure': {
    title: 'Information Exposure',
    description: 'Information exposure vulnerabilities occur when sensitive data is unintentionally made accessible to unauthorized parties. This includes exposed files, directories, configuration details, or API endpoints.',
    impact: 'Exposed information can reveal system architecture, credentials, API keys, source code, database structure, and user data. This information aids attackers in planning more sophisticated attacks.',
    remediation: 'Remove or restrict access to sensitive files and directories. Implement proper access controls. Use .htaccess or web server configurations to deny access. Audit publicly accessible resources regularly.'
  },

  // Misconfig
  'misconfig': {
    title: 'Security Misconfiguration',
    description: 'Security misconfiguration vulnerabilities arise from insecure default configurations, incomplete configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages containing sensitive information.',
    impact: 'Misconfigurations can lead to unauthorized access, information disclosure, privilege escalation, and provide attackers with valuable information about the system architecture and potential attack vectors.',
    remediation: 'Implement security hardening guidelines. Use automated configuration management. Regularly audit configurations. Follow principle of least privilege. Disable unnecessary features and services.'
  }
}

// Function to get description for a vulnerability
export function getVulnDescription(vulnerability) {
  // ALWAYS use the Nuclei/template description if it exists (matches HTML report behavior)
  // This ensures web UI shows same descriptions as HTML report
  const desc = vulnerability.description?.trim()
  if (desc && desc.length > 0) {
    return {
      description: desc,
      source: 'template'
    }
  }

  // IMPORTANT: If no description in vulnerability data, DO NOT use generic fallbacks
  // Return a minimal message and the actual template description should come from backend
  console.warn('[Reconator] Missing description for vulnerability:', vulnerability.name, vulnerability)

  // Only use fallback descriptions if no description exists in the vulnerability data
  const identifier = `${vulnerability.template_id || ''} ${vulnerability.name || ''}`.toLowerCase()
  const vulnType = (vulnerability.type || '').toLowerCase()

  // Try to match by type
  for (const [key, data] of Object.entries(VULN_DESCRIPTIONS)) {
    if (vulnType.includes(key)) {
      return {
        ...data,
        source: 'fallback'
      }
    }
  }

  // Try to match by template_id or name (reuse identifier from above)
  if (identifier.includes('xss') || identifier.includes('cross-site scripting')) {
    return { ...VULN_DESCRIPTIONS['xss'], source: 'matched' }
  }
  if (identifier.includes('lfi') || identifier.includes('file inclusion')) {
    return { ...VULN_DESCRIPTIONS['lfi'], source: 'matched' }
  }
  if (identifier.includes('sqli') || identifier.includes('sql injection')) {
    return { ...VULN_DESCRIPTIONS['sqli'], source: 'matched' }
  }
  if (identifier.includes('ssrf')) {
    return { ...VULN_DESCRIPTIONS['ssrf'], source: 'matched' }
  }
  if (identifier.includes('redirect')) {
    return { ...VULN_DESCRIPTIONS['open-redirect'], source: 'matched' }
  }
  if (identifier.includes('cors')) {
    return { ...VULN_DESCRIPTIONS['cors'], source: 'matched' }
  }
  if (identifier.includes('cve-')) {
    return { ...VULN_DESCRIPTIONS['cve'], source: 'matched' }
  }
  if (identifier.includes('outdated') || identifier.includes('eol') || identifier.includes('end-of-life')) {
    return { ...VULN_DESCRIPTIONS['outdated-software'], source: 'matched' }
  }
  if (identifier.includes('default') || identifier.includes('weak credential')) {
    return { ...VULN_DESCRIPTIONS['default-login'], source: 'matched' }
  }
  if (identifier.includes('exposure') || identifier.includes('exposed')) {
    return { ...VULN_DESCRIPTIONS['exposure'], source: 'matched' }
  }
  if (identifier.includes('misconfig')) {
    return { ...VULN_DESCRIPTIONS['misconfig'], source: 'matched' }
  }

  // Return template description or generic fallback
  return {
    description: vulnerability.description || 'Security vulnerability detected by automated scanning. Review the finding details and remediate according to your security policies.',
    source: 'fallback'
  }
}
