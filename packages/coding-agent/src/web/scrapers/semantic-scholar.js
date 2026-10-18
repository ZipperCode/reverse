import { tryParseJson } from "@rva/utils";
import { buildResult, formatNumber, loadPage } from "./types";
function extractPaperId(url) {
    const patterns = [
        /semanticscholar\.org\/paper\/[^/]+\/([a-f0-9]{40})/i,
        /semanticscholar\.org\/paper\/([a-f0-9]{40})/i,
        /api\.semanticscholar\.org\/.*\/paper\/([a-f0-9]{40})/i,
    ];
    for (const pattern of patterns) {
        const match = url.match(pattern);
        if (match?.[1])
            return match[1];
    }
    return null;
}
export const handleSemanticScholar = async (url, timeout, signal) => {
    if (!url.includes("semanticscholar.org"))
        return null;
    const paperId = extractPaperId(url);
    if (!paperId) {
        return buildResult("Failed to extract paper ID from Semantic Scholar URL", {
            url,
            method: "semantic-scholar",
            fetchedAt: new Date().toISOString(),
            notes: ["Invalid URL format"],
            contentType: "text/plain",
        });
    }
    const fields = [
        "title",
        "abstract",
        "authors",
        "year",
        "citationCount",
        "referenceCount",
        "fieldsOfStudy",
        "publicationTypes",
        "journal",
        "externalIds",
        "tldr",
        "openAccessPdf",
    ].join(",");
    const apiUrl = `https://api.semanticscholar.org/graph/v1/paper/${paperId}?fields=${fields}`;
    const { content, ok, finalUrl } = await loadPage(apiUrl, { timeout, signal });
    if (!ok || !content) {
        return buildResult("Failed to fetch paper from Semantic Scholar API", {
            url,
            finalUrl: apiUrl,
            method: "semantic-scholar",
            fetchedAt: new Date().toISOString(),
            notes: ["API request failed"],
            contentType: "text/plain",
        });
    }
    const paper = tryParseJson(content);
    if (!paper) {
        return buildResult("Failed to parse response from Semantic Scholar API", {
            url,
            finalUrl: apiUrl,
            method: "semantic-scholar",
            fetchedAt: new Date().toISOString(),
            notes: ["JSON parse error"],
            contentType: "text/plain",
        });
    }
    const sections = [];
    sections.push(`# ${paper.title || "Untitled"}`);
    sections.push("");
    if (paper.authors && paper.authors.length > 0) {
        const authorList = paper.authors.map(a => a.name).join(", ");
        sections.push(`**Authors:** ${authorList}`);
        sections.push("");
    }
    const metadata = [];
    if (paper.year)
        metadata.push(`Year: ${paper.year}`);
    if (paper.journal?.name)
        metadata.push(`Venue: ${paper.journal.name}`);
    if (paper.citationCount !== undefined) {
        metadata.push(`Citations: ${formatNumber(paper.citationCount)}`);
    }
    if (paper.referenceCount !== undefined) {
        metadata.push(`References: ${formatNumber(paper.referenceCount)}`);
    }
    if (metadata.length > 0) {
        sections.push(metadata.join(" • "));
        sections.push("");
    }
    if (paper.fieldsOfStudy && paper.fieldsOfStudy.length > 0) {
        sections.push(`**Fields:** ${paper.fieldsOfStudy.join(", ")}`);
        sections.push("");
    }
    if (paper.tldr?.text) {
        sections.push("## TL;DR");
        sections.push("");
        sections.push(paper.tldr.text);
        sections.push("");
    }
    if (paper.abstract) {
        sections.push("## Abstract");
        sections.push("");
        sections.push(paper.abstract);
        sections.push("");
    }
    const links = [];
    if (paper.openAccessPdf?.url) {
        links.push(`[PDF](${paper.openAccessPdf.url})`);
    }
    if (paper.externalIds?.ArXiv) {
        links.push(`[arXiv](https://arxiv.org/abs/${paper.externalIds.ArXiv})`);
    }
    if (paper.externalIds?.DOI) {
        links.push(`[DOI](https://doi.org/${paper.externalIds.DOI})`);
    }
    if (paper.externalIds?.PubMed) {
        links.push(`[PubMed](https://pubmed.ncbi.nlm.nih.gov/${paper.externalIds.PubMed}/)`);
    }
    links.push(`[Semantic Scholar](https://www.semanticscholar.org/paper/${paper.paperId})`);
    if (links.length > 0) {
        sections.push("## Links");
        sections.push("");
        sections.push(links.join(" • "));
        sections.push("");
    }
    const fullContent = sections.join("\n");
    return buildResult(fullContent, { url, finalUrl, method: "semantic-scholar", fetchedAt: new Date().toISOString() });
};
