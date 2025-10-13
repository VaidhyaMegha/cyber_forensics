# Netlas.io Integration

## Why We Use It

Netlas.io is our primary tool for domain intelligence and attack surface discovery. It was chosen as a replacement for SecurityTrails due to its generous free tier and comprehensive data offerings. It allows us to gather deep insights into a domain's infrastructure, which is essential for forensic analysis.

## What We Get

Even on the free plan, Netlas.io provides a wealth of information, including:

- **DNS Records**: Current A, AAAA, MX, NS, and other DNS records.
- **IP Information**: Geolocation, associated domains, and open ports.
- **WHOIS Data**: Domain registration details.
- **SSL Certificate Information**: Details about the SSL/TLS certificate used.
- **Subdomain Enumeration**: A list of known subdomains.
- **Attack Surface Discovery**: An overview of a domain's exposed assets.

## How It Helps the Project

Netlas.io is a cost-effective powerhouse for our toolkit. It allows us to:

- **Map Infrastructure**: Understand how a target domain is set up and hosted.
- **Discover Connections**: Find related domains and IPs that might be part of a larger malicious campaign.
- **Gather Evidence**: Collect crucial data points for the final forensic report without incurring high costs.

## Plans and Pricing

We currently use the **Community (Free)** plan, which is highly capable.

### Community Plan (Free)

- **API Requests**: 50 requests per day.
- **Results**: Up to 200 results per download.
- **Features**: Includes essential tools like internet scan data, DNS & IP WHOIS lookups, and limited Attack Surface Discovery.

### Paid Plans

Netlas.io offers several paid tiers for users who need more data or advanced features:

- **Freelancer ($49/month)**: Increases limits to 1,000 requests/day and adds features like Domain WHOIS and SSL certificate lookups.
- **Business ($249/month)**: The first tier to include **Threat Intelligence data (IOCs)**, proxy/VPN detection, and higher limits (10,000 requests/day).
- **Corporate/Enterprise (Custom Pricing)**: Offer unlimited requests and full data access for large teams.

For this project, the free plan provides more than enough data to build a robust forensic analysis.
