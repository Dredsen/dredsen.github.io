*Author: [Dredsen](https://dredsen.github.io/)*

---

Recently, Cloudflare updated how they handle reporting websites for violations through their phishing report page:

[https://abuse.cloudflare.com/phishing](https://abuse.cloudflare.com/phishing)

Their solution appears to be automation, possibly AI-assisted, to help process the volume of abuse reports they receive. I understand why Cloudflare would want that. They sit in front of a massive part of the internet, and manual review for every single report probably does not scale.

The problem is that this seems to have opened up a new way to attack hosts using Cloudflare for DDoS protection, DNS protection, and similar services, especially anyone using the free plan.

When you go to the link above, you get a template to fill out so you can report a website using Cloudflare. During my testing, almost nothing on the form appeared to matter besides the "Evidence URLs" field. The form also allowed anonymous reports, and I did not run into any meaningful visible rate limiting while testing.

I am sure most people reading this already understand how that can be abused.

To demonstrate the issue, I wrote a quick Python script that automatically filled out the form with bogus information and reported my own personal `.dev` domain. That domain was running behind Cloudflare on the free plan. The site itself was basically an online resume with citations to projects I have worked on and organizations I have signed NDAs with.

I chose the phishing category because it is broad, but based on how the form behaved at the time, I do not think phishing was special here. Other report categories likely would have worked too.

I ran the script against my own domain and sent a small batch of reports over time using different residential IPs. By the next morning, I received this lovely email:

```
Hello,

Cloudflare received an Network abuse regarding: ***CensoredDomain***.dev

If you have questions about this abuse report, please send an email to abusereply@cloudflare.com with the following details:

- The report identification number included in the subject line

- Any additional details, context or evidence you can provide regarding the content that was reported.

Below is the report we received:

Report ID: 2ff901ccd3d21f0a

Logs or other evidence of abuse:

Reported URLs:

https://***CensoredDomain***.dev

This report was handled automatically and this email is an automated reply.

Cloudflare Trust & Safety
```

Currently, anyone who goes to my domain sees this malware warning page. I now need to wait for Cloudflare to get back to my support email, which will probably take at least a week:

![Cloudflare malware warning page](assets/images/cloudflare-malware-warning.png)

This can be used against websites that rely on Cloudflare's free plan for protection. I would not be surprised if it also works against some Pro plan sites, although I have not fully tested that.

I also tried the same idea, with permission, against a friend's domain on the Business plan. I sent more reports than I used against my own free-plan domain, and after 72 hours nothing happened. That does not prove Business plan sites are immune, but it does suggest Cloudflare either has someone verifying reports at that level, has stricter thresholds, or handles those customers through a different process.

The main issue here is not that Cloudflare uses automation. They probably have to. The issue is that anonymous, low-quality reports should not be enough to place a malware warning in front of a clean site, especially when the owner is then stuck waiting on support to undo it.

For a personal site, this is annoying. For a small business, journalist, open source project, or anyone else depending on Cloudflare because they cannot afford more expensive protection, this becomes a real takedown method.

## What Cloudflare could do to limit this

I do not think Cloudflare needs to remove anonymous reporting entirely. Anonymous reports can be important. The issue is letting anonymous, low-effort reports trigger visible warnings without enough verification.

A few things that could help:

- Check whether the report looks like it came from a real browser or an automated script. `User-Agent` headers alone are easy to fake, but they can still be one signal alongside missing browser headers, strange header order, no JavaScript execution, no normal form timing, repeated identical submissions, or requests that never load the page normally.
- Add a real bot check to the abuse form, such as Cloudflare Turnstile. It would not stop everything, but it would raise the cost for lazy automation.
- Require email verification before a report can influence automated enforcement. A user could still submit the report immediately, but Cloudflare should not let it count toward takedown action until the reporter verifies the email address.
- Rate limit reports by more than IP address. Cloudflare could look at reporter email, ASN, network reputation, browser fingerprint, target domain, report category, and repeated evidence URLs.
- Treat bursts of reports against one domain as suspicious by default, especially when the reports have similar wording, similar metadata, or all point to the same root URL without detailed evidence.
- Actually fetch and inspect the evidence URL before action. If the report says phishing, check whether the page contains credential fields, brand impersonation, suspicious redirects, or other phishing indicators instead of relying on the submitted URL alone.
- Separate intake from enforcement. Let anyone submit a report, but require a higher confidence score or human review before showing a malware or phishing warning to visitors.
- Give site owners better appeal information. The email I received included no useful evidence, no screenshot, no explanation, and no reason beyond the reported URL. That makes it hard to respond quickly.
- Add a fast appeal path for false automated warnings, including for free-plan users. If the warning was applied automatically, there should be an equally fast way to get a human review.

None of these fixes are perfect on their own. The goal should be to make abuse expensive enough that someone cannot point a simple script at a clean site and cause real downtime by the next morning.
