*Author: [Dredsen](https://dredsen.github.io/)*

---

You found a vulnerable driver. Now what?

This post walks through exactly what to do next - who to tell, how to tell them, and how to get a CVE number assigned. No experience required. I'm figuring this out as I go too, so this is written to be as plain as possible.

---

## Step 1 - Make Sure You Actually Have Something

Before you report anything, make sure you can clearly answer these three questions:

1. **What is the bug?** - e.g. "the driver maps arbitrary physical memory to user space through IOCTL `0x223EF4` with no access control"
2. **What can an attacker do with it?** - e.g. "any local user can read arbitrary physical memory without any privileges"
3. **Can you reproduce it?** - if you can trigger it reliably, document the steps

You don't need a full working exploit. You do need to be specific enough that whoever receives your report can understand and verify the issue without guessing.

Write it down clearly before you send anything. A well-documented report gets taken seriously. A vague one gets ignored.

---

## Step 2 - Who to Report To

There are a few different places to report, and you'll often report to more than one. Here's who they are and what they do:

### The Vendor (Most Important)

The vendor is the company that made the driver - Broadcom, Intel, Dell, whoever. Reporting to them first is called **coordinated disclosure**, and it's the standard expected approach. It gives them a chance to fix the issue before it becomes public.

**How to find their security contact:**
- Look for `security@[vendor].com` or a dedicated security page (e.g. `[vendor].com/security`)
- Search `[vendor name] vulnerability disclosure` or `[vendor name] PSIRT` (Product Security Incident Response Team)
- Check their website footer for a "Responsible Disclosure" or "Security Research" link

**What to send:**
- A short description of the vulnerability
- The affected product/driver name, version, and hashes
- What an attacker can do with it
- Steps to reproduce (even rough ones)
- Your contact info and a preferred response timeline

Keep the initial email short and clear. You're not writing a novel - you're opening a conversation.

### LOLDrivers (GitHub)

[LOLDrivers](https://www.loldrivers.io/) is a community-maintained list of vulnerable signed Windows drivers. If your driver isn't already listed there, you can submit it by opening a Pull Request on their [GitHub repo](https://github.com/magicsword-io/LOLDrivers).

They have a YAML template for submissions. Fill it out with the driver details and your findings. This gets the information into the hands of detection engineers and blue teamers regardless of whether the vendor ever patches it.

### Microsoft

If the driver is WHQL-signed (certified by Microsoft) or the vulnerability enables a **Driver Signature Enforcement bypass**, you can report directly to Microsoft Security Response Center (MSRC):

**[msrc.microsoft.com/create-report](https://msrc.microsoft.com/create-report)**

Microsoft can revoke the driver's certificate or add it to their vulnerable driver blocklist, which gets pushed to Windows Defender.

### CERT/CC (Optional Escalation)

If the vendor is unresponsive, the vulnerability is severe, or you don't know who the vendor is - [CERT/CC](https://www.kb.cert.org/vuls/report/) at Carnegie Mellon University acts as a neutral third party. They can help coordinate disclosure and pressure vendors who aren't responding.

You don't have to use them for every report, but they're useful to know about.

---

## Step 3 - The 90-Day Clock

The industry standard for coordinated disclosure is **90 days**. When you report to a vendor, give them 90 days to release a fix before you go public with the details.

This isn't a hard legal rule - it's a norm. Google Project Zero popularised it and most researchers follow it. The reasoning: vendors need time to investigate and patch, but an indefinite embargo just protects them at the expense of users who are running vulnerable software.

**In practice:**

1. Send your report and note the date
2. If the vendor acknowledges it, coordinate a disclosure date with them
3. If the vendor doesn't respond within a couple of weeks, follow up
4. If 90 days pass with no fix and no reasonable explanation, it's standard practice to disclose anyway - with a note that the vendor was notified and didn't respond

Keep a record of all emails and timestamps. If you ever need to explain your disclosure timeline, the receipts matter.

---

## Step 4 - Getting a CVE

A CVE (Common Vulnerabilities and Exposures) is just a unique ID assigned to a specific vulnerability - like `CVE-2024-12345`. It's the standard way vulnerabilities are tracked and referenced.

CVEs are assigned by **CVE Numbering Authorities (CNAs)**. Here's how to get one:

### Route A - The Vendor Assigns It (Easiest)

If the vendor is a CNA themselves (most large companies are), they'll assign a CVE number as part of handling your report. Just ask them to. They'll do the paperwork.

### Route B - MITRE (Most Common for Independent Researchers)

If the vendor isn't a CNA, or isn't cooperating, you can request a CVE directly from MITRE - the organisation that runs the CVE programme.

**Request form:** [cveform.mitre.org](https://cveform.mitre.org)

What to fill in:
- **Vulnerability type** - e.g. "Improper Access Control", "Exposed Dangerous Method"
- **Vendor/product** - who made it, what's affected
- **Version** - the specific driver version or hash
- **Description** - a clear one or two sentence summary of the bug and its impact
- **Attack type** - Local / Remote / Physical
- **Impact** - Confidentiality / Integrity / Availability
- **References** - your write-up URL, if you have one (you can update this later)

MITRE will review and assign a CVE ID. It can take a few days to a few weeks. Once assigned, you'll get an email with the number.

### Route C - GitHub Security Advisories (If There's a Repo)

If the vulnerable code has a public GitHub repository, you can create a **GitHub Security Advisory** directly from that repo. GitHub is a CNA and can assign CVEs through this process automatically. Less relevant for closed-source vendor drivers, but useful to know.

---

## Step 5 - Going Public

Once the vendor has released a patch (or your 90 days are up), you're clear to publish your write-up. At this point:

- Update your write-up with the assigned CVE number
- Update your LOLDrivers submission with the CVE
- Update the MITRE entry with a link to your write-up (you can do this by contacting them)
- Post about it - write it up, put it on your blog, share it

If there's no patch and you're disclosing anyway, be clear about that in the post. Note the date you reported, the date you followed up, and that no fix was issued. Don't be dramatic about it - just state the facts.

---

## Quick Reference

| Who | What for | Link |
|---|---|---|
| Vendor PSIRT | Coordinated disclosure | Search `[vendor] security disclosure` |
| LOLDrivers | Add to public driver catalogue | [github.com/magicsword-io/LOLDrivers](https://github.com/magicsword-io/LOLDrivers) |
| Microsoft MSRC | WHQL drivers / DSE bypass | [msrc.microsoft.com/create-report](https://msrc.microsoft.com/create-report) |
| MITRE CVE | Request a CVE number | [cveform.mitre.org](https://cveform.mitre.org) |
| CERT/CC | Vendor not responding | [kb.cert.org/vuls/report](https://www.kb.cert.org/vuls/report/) |

---

## Example Disclosure Email

This is roughly the structure I'd use for an initial vendor report. Keep it short - they'll ask for more if they need it.

```
Subject: [Security] Vulnerability Report - [Driver Name] [Version]

Hello,

I'm reporting a vulnerability in [Driver Name] ([filename], SHA256: [hash]).

Summary:
[One or two sentences describing the bug and its impact.]

Details:
- Affected file: [filename], version [x.x.x]
- Vulnerability: [Brief technical description]
- Impact: [What an attacker can do]
- Prerequisites: [e.g. local user access, no special privileges required]

Reproduction:
[Short steps to reproduce, or a description of the affected code path]

I'm following a 90-day coordinated disclosure timeline from the date of this email.
Please confirm receipt and let me know if you need additional information.

Regards,
[Your name / handle]
[Contact info]
```

---

That's the full process. It sounds like a lot written out, but in practice it's: write up your findings, email the vendor, request a CVE from MITRE, wait 90 days, publish. Most of the time is just waiting.

If you have questions or I've got something wrong here, corrections are always welcome.
