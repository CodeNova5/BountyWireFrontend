import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import OpenAI from 'openai';
import { z } from 'zod';
import dns from 'dns';

// 1. Vercel max execution time — 5 minutes
export const maxDuration = 300;

// ---------------------------------------------------------------------------
// Client initialization
// ---------------------------------------------------------------------------
const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
);

const aiClient = new OpenAI({
    baseURL: 'https://api.groq.com/openai/v1',
    apiKey: process.env.GROQ_API_KEY!,
});

// ---------------------------------------------------------------------------
// Zod schema — enforces strict structured output from the AI
// ---------------------------------------------------------------------------
const TakeoverAnalysisSchema = z.object({
    is_vulnerable: z.boolean(),
    confidence: z.enum(['High', 'Medium', 'Low']),
    reasoning: z.string(),
    signature_found: z.string(),
});

type TakeoverAnalysis = z.infer<typeof TakeoverAnalysisSchema>;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface SubdomainResult {
    subdomain: string;
    cname: string | null;
    ipAddresses: string[];
    httpStatus: number | null;
    error: string | null;
}

// ---------------------------------------------------------------------------
// Helper: write an agent thought to Supabase Realtime
// ---------------------------------------------------------------------------
async function logAgentThought(
    targetId: string,
    stepName: string,
    message: string,
    logLevel: 'info' | 'warning' | 'critical' = 'info'
): Promise<void> {
    const { error } = await supabase.from('agent_logs').insert({
        target_id: targetId,
        step_name: stepName,
        log_level: logLevel,
        message,
    });
    if (error) {
        console.error('[logAgentThought] Supabase insert error:', error.message);
    }
}

// ---------------------------------------------------------------------------
// Helper: probe a single subdomain (CNAME → A-record → HTTP status)
// ---------------------------------------------------------------------------
async function probeSubdomain(subdomain: string): Promise<SubdomainResult> {
    const result: SubdomainResult = {
        subdomain,
        cname: null,
        ipAddresses: [],
        httpStatus: null,
        error: null,
    };

    // --- CNAME lookup ---
    try {
        const cnameRecords = await dns.promises.resolveCname(subdomain);
        result.cname = cnameRecords[0] ?? null;
    } catch {
        // CNAME not found — fall through to A-record
    }

    // --- A-record fallback ---
    if (!result.cname) {
        try {
            result.ipAddresses = await dns.promises.resolve4(subdomain);
        } catch {
            result.error = 'No DNS record found (CNAME or A)';
            return result; // Nothing resolves — skip HTTP check
        }
    }

    // --- HTTP status probe ---
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const response = await fetch(`http://${subdomain}`, {
            method: 'GET',
            signal: controller.signal,
            redirect: 'follow',
        });
        clearTimeout(timeout);
        result.httpStatus = response.status;
    } catch (fetchErr: unknown) {
        const msg = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
        // Not a fatal error — many subdomains are HTTPS-only or firewalled
        result.httpStatus = null;
        result.error = `HTTP probe failed: ${msg}`;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Helper: check if a CNAME points to a known cloud provider (takeover surface)
// ---------------------------------------------------------------------------
const CLOUD_TAKEOVER_PATTERNS: RegExp[] = [
    /\.wordpress\.com$/i,
    /\.github\.io$/i,
    /\.vercel\.app$/i,
    /\.netlify\.app$/i,
    /\.cloudfront\.net$/i,
    /\.s3\.amazonaws\.com$/i,
    /\.s3-website[-.]/i,
    /\.azurewebsites\.net$/i,
    /\.azureedge\.net$/i,
    /\.myshopify\.com$/i,
    /\.ghost\.io$/i,
    /\.webflow\.io$/i,
    /\.surge\.sh$/i,
    /\.herokudns\.com$/i,
    /\.fastly\.net$/i,
    /\.pantheonsite\.io$/i,
    /\.readthedocs\.io$/i,
    /\.cargo\.site$/i,
    /\.readme\.io$/i,
    /\.helpscoutdocs\.com$/i,
    /\.zendesk\.com$/i,
    /\.freshdesk\.com$/i,
    /\.statuspage\.io$/i,
];

function matchesCloudProvider(cname: string): string | null {
    for (const pattern of CLOUD_TAKEOVER_PATTERNS) {
        if (pattern.test(cname)) {
            return cname;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Helper: first AI call — classify vulnerability
// ---------------------------------------------------------------------------
async function analyzeForTakeover(probe: SubdomainResult): Promise<TakeoverAnalysis | null> {
    const prompt = `You are an expert Automated Bug Bounty Agent performing subdomain takeover analysis.

Analyze the following live asset data collected from real DNS and HTTP reconnaissance:

  Subdomain   : ${probe.subdomain}
  CNAME Record: ${probe.cname ?? 'None'}
  A-Records   : ${probe.ipAddresses.length > 0 ? probe.ipAddresses.join(', ') : 'None'}
  HTTP Status : ${probe.httpStatus ?? 'Unreachable / Timed-Out'}
  Probe Error : ${probe.error ?? 'None'}

Determine if this asset is vulnerable to a Subdomain Takeover attack.
A subdomain is likely vulnerable when it has an active CNAME pointing to an unclaimed or deprovisioned service
on a cloud platform (e.g., *.github.io, *.wordpress.com, *.vercel.app, *.s3.amazonaws.com)
AND the HTTP probe returns a 404, connection refused, or timed-out — indicating the backing resource no longer exists.

Respond EXCLUSIVELY with a raw JSON object matching this exact schema (no markdown, no extra keys):
{
  "is_vulnerable": true or false,
  "confidence": "High" or "Medium" or "Low",
  "reasoning": "detailed single-paragraph explanation of your decision",
  "signature_found": "the specific signature or string that indicates the vulnerability, or 'N/A'"
}`;

    try {
        const completion = await aiClient.chat.completions.create({
            model: 'openai/gpt-oss-20b',
            messages: [{ role: 'user', content: prompt }],
            response_format: { type: 'json_object' },
            temperature: 0.1,
        });

        const rawContent = completion.choices[0]?.message?.content ?? '{}';
        return TakeoverAnalysisSchema.parse(JSON.parse(rawContent));
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error('[analyzeForTakeover] AI/parse error:', msg);
        return null;
    }
}

// ---------------------------------------------------------------------------
// Helper: second AI call — generate professional remediation report (Markdown)
// ---------------------------------------------------------------------------
async function generateRemediationReport(
    probe: SubdomainResult,
    analysis: TakeoverAnalysis
): Promise<string> {
    const prompt = `You are a senior application security engineer writing a professional bug bounty vulnerability report.

The following subdomain takeover vulnerability has been confirmed by an automated reconnaissance agent:

  Target Subdomain : ${probe.subdomain}
  Dangling CNAME   : ${probe.cname ?? 'N/A'}
  HTTP Status      : ${probe.httpStatus ?? 'Unreachable'}
  Confidence Level : ${analysis.confidence}
  Agent Reasoning  : ${analysis.reasoning}
  Signature Found  : ${analysis.signature_found}

Generate a COMPLETE, professional, copy-pasteable Markdown security report with the following sections:

# Subdomain Takeover — ${probe.subdomain}

## Executive Summary
(2–3 sentences for a non-technical audience)

## Vulnerability Description
(Technical explanation of subdomain takeover, what a dangling CNAME is, and why this is exploitable)

## Affected Asset
(Table with: Subdomain, CNAME Target, HTTP Status, Severity)

## Proof of Concept / Evidence
(Step-by-step reproduction instructions an auditor can follow)

## Business Impact
(Real-world consequences: phishing, credential harvesting, cookie theft, etc.)

## Step-by-Step Remediation
(Numbered, copy-pasteable DNS fix instructions for the engineering team)

## References
(CVEs, OWASP, HackerOne reports, or other authoritative links)

Write the full report now. Do not truncate. Do not add any text before or after the Markdown.`;

    try {
        const completion = await aiClient.chat.completions.create({
            model: 'openai/gpt-oss-20b',
            messages: [{ role: 'user', content: prompt }],
            temperature: 0.3,
            max_tokens: 2048,
        });

        return completion.choices[0]?.message?.content?.trim() ?? `# Report Generation Failed\n\nThe AI model did not return content for ${probe.subdomain}.`;
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error('[generateRemediationReport] AI error:', msg);
        return `# Report Generation Error\n\n${msg}`;
    }
}

// ---------------------------------------------------------------------------
// POST /api/scan — main handler
// ---------------------------------------------------------------------------
export async function POST(request: Request) {
    let targetId: string | null = null;
    let domain = '';

    try {
        const body = await request.json();
        domain = (body.domain ?? '').trim().toLowerCase();

        if (!domain) {
            return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
        }

        // -----------------------------------------------------------------------
        // Step 0: Create target record
        // -----------------------------------------------------------------------
        const { data: targetData, error: targetError } = await supabase
            .from('targets')
            .insert({ domain, status: 'scanning' })
            .select()
            .single();

        if (targetError) throw new Error(`Failed to create target: ${targetError.message}`);
        targetId = targetData.id as string;

        await logAgentThought(
            targetId,
            'Initialization',
            `BountyWire Agent v2 initialized. Target domain: ${domain}. Beginning active DNS reconnaissance.`
        );

        // -----------------------------------------------------------------------
        // Step 1: Define target subdomains for active enumeration
        // -----------------------------------------------------------------------
        const prefixes = ['dev', 'marketing', 'status', 'shop', 'blog', 'api', 'staging', 'admin'];
        const subdomainsToProbe = prefixes.map((p) => `${p}.${domain}`);

        await logAgentThought(
            targetId,
            'Enumeration',
            `Queuing ${subdomainsToProbe.length} subdomains for active DNS probing: ${subdomainsToProbe.join(', ')}`
        );

        // -----------------------------------------------------------------------
        // Step 2: DNS + HTTP reconnaissance loop
        // -----------------------------------------------------------------------
        const probeResults: SubdomainResult[] = [];

        for (const subdomain of subdomainsToProbe) {
            await logAgentThought(
                targetId,
                'DNS Probe',
                `Resolving ${subdomain} — attempting CNAME lookup, then A-record fallback...`
            );

            const probe = await probeSubdomain(subdomain);
            probeResults.push(probe);

            if (probe.error && !probe.cname && probe.ipAddresses.length === 0) {
                await logAgentThought(
                    targetId,
                    'DNS Probe',
                    `${subdomain} → No DNS records found. Skipping. (${probe.error})`,
                    'info'
                );
                continue;
            }

            const cnameInfo = probe.cname ? `CNAME → ${probe.cname}` : `A-record → ${probe.ipAddresses.join(', ')}`;
            const httpInfo = probe.httpStatus ? `HTTP ${probe.httpStatus}` : 'HTTP unreachable';

            await logAgentThought(
                targetId,
                'DNS Probe',
                `${subdomain} resolved: ${cnameInfo} | ${httpInfo}${probe.error ? ` | Note: ${probe.error}` : ''}`
            );

            // Insert subdomain record
            try {
                await supabase.from('subdomains').insert({
                    target_id: targetId,
                    subdomain,
                    cname: probe.cname,
                    http_status: probe.httpStatus,
                    live_status: probe.httpStatus && probe.httpStatus < 500 ? 'live' : 'unknown',
                });
            } catch {
                // Non-fatal — subdomain logging should never abort the scan
            }
        }

        // -----------------------------------------------------------------------
        // Step 3: Agentic analysis loop — evaluate candidates for takeover
        // -----------------------------------------------------------------------
        await logAgentThought(
            targetId,
            'Analysis Loop',
            `Reconnaissance complete. Evaluating ${probeResults.length} probed subdomains for takeover indicators...`
        );

        let vulnerabilitiesFound = 0;

        for (const probe of probeResults) {
            // Skip subdomains with no DNS data at all
            if (!probe.cname && probe.ipAddresses.length === 0) continue;

            // Only send to AI if: has a cloud-provider CNAME AND (HTTP 404 or unreachable)
            const isCloudCname = probe.cname ? matchesCloudProvider(probe.cname) : null;
            const isSuspectStatus =
                probe.httpStatus === null || probe.httpStatus === 404 || probe.httpStatus === 410;

            if (!isCloudCname || !isSuspectStatus) {
                await logAgentThought(
                    targetId,
                    'Analysis Loop',
                    `${probe.subdomain} → Not a takeover candidate (CNAME: ${probe.cname ?? 'none'}, HTTP: ${probe.httpStatus ?? 'N/A'}). Skipping AI analysis.`
                );
                continue;
            }

            await logAgentThought(
                targetId,
                'Analysis Loop',
                `⚠ Suspicious pattern detected on ${probe.subdomain}: CNAME points to ${probe.cname} (cloud provider) with HTTP ${probe.httpStatus ?? 'unreachable'}. Escalating to AI analysis...`,
                'warning'
            );

            // --- First AI call: classify vulnerability ---
            const analysis = await analyzeForTakeover(probe);

            if (!analysis) {
                await logAgentThought(
                    targetId,
                    'Analysis Loop',
                    `AI analysis failed for ${probe.subdomain}. Skipping.`,
                    'warning'
                );
                continue;
            }

            await logAgentThought(
                targetId,
                'Takeover Verification',
                `AI verdict for ${probe.subdomain}: is_vulnerable=${analysis.is_vulnerable}, confidence=${analysis.confidence}. Reasoning: ${analysis.reasoning}`,
                analysis.is_vulnerable ? 'warning' : 'info'
            );

            if (analysis.is_vulnerable) {
                vulnerabilitiesFound++;

                // Fetch subdomain DB record id for FK
                const { data: subRow } = await supabase
                    .from('subdomains')
                    .select('id')
                    .eq('target_id', targetId)
                    .eq('subdomain', probe.subdomain)
                    .maybeSingle();

                // --- Second AI call: generate remediation report ---
                await logAgentThought(
                    targetId,
                    'Report Generation',
                    `Generating professional remediation advisory report for ${probe.subdomain}...`
                );

                const remediationReport = await generateRemediationReport(probe, analysis);

                await logAgentThought(
                    targetId,
                    'Report Generation',
                    `Remediation report generated (${remediationReport.length} chars). Saving to vulnerabilities table...`
                );

                // Save vulnerability with full Markdown report in evidence column
                await supabase.from('vulnerabilities').insert({
                    target_id: targetId,
                    subdomain_id: subRow?.id ?? null,
                    vuln_type: 'Subdomain Takeover',
                    severity: analysis.confidence === 'High' ? 'Critical' : analysis.confidence === 'Medium' ? 'High' : 'Medium',
                    evidence: remediationReport,
                });

                await logAgentThought(
                    targetId,
                    'Takeover Verification',
                    `🚨 VULNERABILITY CONFIRMED on ${probe.subdomain} [${analysis.confidence} confidence]. Dangling CNAME: ${probe.cname}. Full remediation report saved.`,
                    'critical'
                );
            }
        }

        // -----------------------------------------------------------------------
        // Step 4: Finalize
        // -----------------------------------------------------------------------
        const summary =
            vulnerabilitiesFound > 0
                ? `Scan complete. ${vulnerabilitiesFound} subdomain takeover vulnerability(ies) confirmed and reported for ${domain}.`
                : `Scan complete. No subdomain takeover vulnerabilities detected for ${domain}. All probed subdomains appear safe.`;

        await logAgentThought(targetId, 'Completed', summary);
        await supabase.from('targets').update({ status: 'completed' }).eq('id', targetId);

        return NextResponse.json({
            success: true,
            target_id: targetId,
            vulnerabilities_found: vulnerabilitiesFound,
            subdomains_probed: probeResults.length,
        });

    } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        console.error('[POST /api/scan] Fatal agent exception:', msg);
        if (targetId) {
            await logAgentThought(targetId, 'Failed', `Critical engine exception: ${msg}`, 'critical');
            await supabase.from('targets').update({ status: 'failed' }).eq('id', targetId);
        }
        return NextResponse.json({ error: msg }, { status: 500 });
    }
}