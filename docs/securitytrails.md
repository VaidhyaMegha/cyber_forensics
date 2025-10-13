# SecurityTrails Integration (Legacy)

## Why We Used It

SecurityTrails was initially integrated into the toolkit to gather historical DNS data, subdomain information, and IP history for a given domain. This kind of historical data is invaluable for forensic investigations, as it can reveal past infrastructure changes and associations.

## Why We Moved to Netlas.io

While SecurityTrails provides excellent data, its free tier was highly restrictive for the needs of a forensic tool. Key limitations included:

- **Low API Quota**: The free plan historically offered around 50 API calls per month, which is insufficient for even light usage.
- **Restricted Data**: Access to crucial historical DNS and IP data required a paid subscription.
- **High Cost**: The paid plans, while powerful, were too expensive for the project's budget. The primary goal was to build a tool that was both effective and accessible, and the cost of SecurityTrails made it prohibitive.

## Plans and Pricing (At the Time of Switch)

### Free Tier

- **API Calls**: Extremely limited (e.g., 50/month).
- **Data Access**: Basic current DNS lookups. No access to historical data, which is a key feature for forensics.

### Paid Plans

- **Tiers**: Offered various tiers (Professional, Enterprise) that unlocked higher API limits and access to their full historical database.
- **Cost**: Subscription-based, ranging from hundreds to thousands of dollars per year depending on the data volume and features required.

Due to these factors, we made the strategic decision to migrate to **Netlas.io**, which offers a much more generous free tier and provides a comparable level of domain intelligence.
