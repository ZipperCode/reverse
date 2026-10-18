import { tryParseJson } from "@rva/utils";
import { buildResult, formatIsoDate, loadPage } from "./types";
/**
 * Handle NVD (National Vulnerability Database) CVE URLs
 */
export const handleNvd = async (url, timeout, signal) => {
    try {
        const parsed = new URL(url);
        if (!parsed.hostname.includes("nvd.nist.gov"))
            return null;
        // Extract CVE ID from /vuln/detail/{CVE-ID}
        const match = parsed.pathname.match(/\/vuln\/detail\/(CVE-\d{4}-\d+)/i);
        if (!match)
            return null;
        const cveId = match[1].toUpperCase();
        const fetchedAt = new Date().toISOString();
        // Fetch from NVD API
        const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
        const result = await loadPage(apiUrl, {
            timeout,
            headers: { Accept: "application/json" },
            signal,
        });
        if (!result.ok)
            return null;
        const data = tryParseJson(result.content);
        if (!data)
            return null;
        const vuln = data.vulnerabilities?.[0]?.cve;
        if (!vuln)
            return null;
        let md = `# ${vuln.id}\n\n`;
        // Status and dates
        if (vuln.vulnStatus) {
            md += `**Status:** ${vuln.vulnStatus}\n`;
        }
        md += `**Published:** ${formatIsoDate(vuln.published)}`;
        md += ` · **Modified:** ${formatIsoDate(vuln.lastModified)}\n\n`;
        // Description
        const desc = vuln.descriptions.find(d => d.lang === "en")?.value;
        if (desc) {
            md += `## Description\n\n${desc}\n\n`;
        }
        // CVSS Scores
        const cvss31 = vuln.metrics?.cvssMetricV31?.[0];
        const cvss30 = vuln.metrics?.cvssMetricV30?.[0];
        const cvss2 = vuln.metrics?.cvssMetricV2?.[0];
        if (cvss31 || cvss30 || cvss2) {
            md += `## CVSS Scores\n\n`;
            if (cvss31) {
                const data = cvss31.cvssData;
                md += `### CVSS 3.1\n\n`;
                md += `- **Base Score:** ${data.baseScore} (${data.baseSeverity})\n`;
                md += `- **Vector:** \`${data.vectorString}\`\n`;
                if (cvss31.exploitabilityScore !== undefined) {
                    md += `- **Exploitability:** ${cvss31.exploitabilityScore}\n`;
                }
                if (cvss31.impactScore !== undefined) {
                    md += `- **Impact:** ${cvss31.impactScore}\n`;
                }
                md += "\n";
            }
            if (cvss30 && !cvss31) {
                const data = cvss30.cvssData;
                md += `### CVSS 3.0\n\n`;
                md += `- **Base Score:** ${data.baseScore} (${data.baseSeverity})\n`;
                md += `- **Vector:** \`${data.vectorString}\`\n`;
                md += "\n";
            }
            if (cvss2) {
                const data = cvss2.cvssData;
                md += `### CVSS 2.0\n\n`;
                md += `- **Base Score:** ${data.baseScore}`;
                if (data.severity)
                    md += ` (${data.severity})`;
                md += `\n- **Vector:** \`${data.vectorString}\`\n\n`;
            }
        }
        // Weaknesses (CWE)
        const cwes = vuln.weaknesses
            ?.flatMap(w => w.description)
            .filter(d => d.lang === "en" && d.value !== "NVD-CWE-Other" && d.value !== "NVD-CWE-noinfo");
        if (cwes?.length) {
            md += `## Weaknesses\n\n`;
            for (const cwe of cwes) {
                md += `- ${cwe.value}\n`;
            }
            md += "\n";
        }
        // Affected Products (CPE)
        const cpes = extractCpes(vuln.configurations);
        if (cpes.length > 0) {
            md += `## Affected Products\n\n`;
            const shown = cpes.slice(0, 20);
            for (const cpe of shown) {
                md += `- \`${cpe}\`\n`;
            }
            if (cpes.length > 20) {
                md += `\n[…${cpes.length - 20} CPEs elided…]\n`;
            }
            md += "\n";
        }
        // References
        if (vuln.references?.length) {
            md += `## References\n\n`;
            for (const ref of vuln.references.slice(0, 15)) {
                const tags = ref.tags?.length ? ` (${ref.tags.join(", ")})` : "";
                md += `- ${ref.url}${tags}\n`;
            }
            if (vuln.references.length > 15) {
                md += `\n[…${vuln.references.length - 15} references elided…]\n`;
            }
        }
        return buildResult(md, { url, method: "nvd", fetchedAt, notes: ["Fetched via NVD API"] });
    }
    catch { }
    return null;
};
function extractCpes(configurations) {
    if (!configurations)
        return [];
    const cpes = [];
    for (const config of configurations) {
        for (const node of config.nodes ?? []) {
            for (const match of node.cpeMatch ?? []) {
                if (match.vulnerable && match.criteria) {
                    cpes.push(match.criteria);
                }
            }
        }
    }
    return Array.from(new Set(cpes));
}
