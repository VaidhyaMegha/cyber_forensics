# VirusTotal Integration

## Why We Use It

VirusTotal is a critical component of our cyber forensics toolkit, used to analyze URLs and files for potential malware, phishing threats, and other malicious content. It aggregates the results from over 70 antivirus scanners and URL/domain blacklisting services, providing a comprehensive and reliable security assessment.

## What We Get

From the VirusTotal API, we obtain:

- **Detection Ratios**: The number of security vendors that flagged the URL as malicious.
- **Analysis Reports**: Detailed results from each individual scanner.
- **Community Score**: A reputation score based on votes from the VirusTotal community.
- **Categorization**: Classification of the URL (e.g., phishing, malware, suspicious).

## How It Helps the Project

This tool is fundamental to our risk assessment module. By leveraging VirusTotal, we can:

- **Quickly Identify Threats**: Instantly determine if a URL is known to be malicious.
- **Provide Actionable Intelligence**: The data helps us calculate a threat score and provide a clear recommendation (e.g., "High Risk," "Clean").
- **Increase Reliability**: Cross-referencing with dozens of scanners provides a much more reliable verdict than relying on a single source.

## Plans and Pricing

We use the **Public API**, which is free but has limitations.

### Public API (Free)

- **Rate Limit**: 500 requests per day and 4 requests per minute.
- **Usage**: Must not be used in commercial products or services.
- **Data**: Provides basic enrichment data, sufficient for the core analysis of this project.

### Premium API (Paid)

- **Limits**: Offers much higher request rates and daily quotas, tailored to business needs.
- **Features**: Returns more detailed threat context, including behavioral information, relationships between indicators, and advanced threat hunting capabilities.
- **Cost**: Pricing is enterprise-level and typically negotiated based on usage, often starting in the thousands of dollars per year. This is beyond the scope and budget of the current project.
