import { NextResponse, after } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import OpenAI from 'openai';
import { z } from 'zod';
import dns from 'dns';

// Force Node.js runtime — required for dns module and long-running scans
export const runtime = 'nodejs';

// Vercel max execution time — 5 minutes
export const maxDuration = 300;

// ---------------------------------------------------------------------------
// Client initialization (lazy to avoid build-time evaluation)
// ---------------------------------------------------------------------------
function getSupabase() {
    return createClient(
        process.env.NEXT_PUBLIC_SUPABASE_URL!,
        process.env.SUPABASE_SERVICE_ROLE_KEY!
    );
}

const GROQ_KEYS = [
    process.env.GROQ_API_KEY,
    process.env.GROQ_API_KEY_1,
].filter((key): key is string => !!key);

let keyIndex = 0;
function getGroqApiKey(): string {
    if (GROQ_KEYS.length === 0) {
        throw new Error('No Groq API keys configured. Please set GROQ_API_KEY in your environment.');
    }
    const apiKey = GROQ_KEYS[keyIndex % GROQ_KEYS.length];
    keyIndex++;
    return apiKey;
}

function getAiClient() {
    return new OpenAI({
        baseURL: 'https://api.groq.com/openai/v1',
        apiKey: getGroqApiKey(),
    });
}

const REACT_MODEL = 'llama-3.3-70b-versatile';


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

interface AgentContext {
    targetId: string;
    domain: string;
    discoveredSubdomains: string[];
    probedSubdomains: Map<string, SubdomainResult>;
    analyzedSubdomains: Set<string>;
    vulnerabilities: Array<{ subdomain: string; analysis: TakeoverAnalysis; probe: SubdomainResult }>;
    currentFocus: string | null;
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
    const { error } = await getSupabase().from('agent_logs').insert({
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
// Helper: log agent reasoning (thought process)
// ---------------------------------------------------------------------------
async function logAgentReasoning(targetId: string, thought: string): Promise<void> {
    await logAgentThought(targetId, 'Agent Reasoning', thought, 'info');
}

// ---------------------------------------------------------------------------
// Helper: log tool call
// ---------------------------------------------------------------------------
async function logToolCall(targetId: string, toolName: string, args: string, result: string): Promise<void> {
    await logAgentThought(targetId, 'Tool Execution', `TOOLS.${toolName}(${args}) => ${result}`, 'info');
}

// ---------------------------------------------------------------------------
// Helper: log tool result
// ---------------------------------------------------------------------------
async function logToolResult(targetId: string, result: string): Promise<void> {
    await logAgentThought(targetId, 'Tool Result', result, 'info');
}

// ---------------------------------------------------------------------------
// Helper: Fetch subdomains from crt.sh JSON API with Retries
// ---------------------------------------------------------------------------
async function fetchSubdomainsFromCrtSh(domain: string): Promise<string[]> {
    const subdomainsSet = new Set<string>();

    const fetchWithRetry = async (url: string, maxRetries = 3, timeoutMs = 25000) => {
        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), timeoutMs);
            try {
                const response = await fetch(url, {
                    signal: controller.signal,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (BountyWire/1.0)',
                        'Accept': 'application/json'
                    }
                });
                clearTimeout(timeout);

                if (!response.ok) throw new Error(`HTTP ${response.status}`);

                const text = await response.text();
                return JSON.parse(text); // Will throw if crt.sh returns an HTML error page
            } catch (err) {
                clearTimeout(timeout);
                if (attempt === maxRetries) throw err;
                // Exponential backoff: 2s, 4s...
                await new Promise(r => setTimeout(r, attempt * 2000));
            }
        }
    };

    // Source 1: Optimized crt.sh Query (using %. wildcard to target subdomains)
    try {
        const data = await fetchWithRetry(`https://crt.sh/?q=%.${domain}&output=json&exclude=expired`, 3, 25000);
        if (Array.isArray(data)) {
            for (const item of data) {
                if (!item.name_value) continue;
                const names = item.name_value.toLowerCase().split('\n');
                for (let name of names) {
                    name = name.replace(/^\*\./, '').trim();
                    if (name && name.endsWith(domain) && name !== domain) {
                        subdomainsSet.add(name);
                    }
                }
            }
        }
    } catch (err) {
        console.warn('[fetchSubdomainsFromCrtSh] crt.sh failed after retries:', err);
    }

    // Source 2: Certspotter API Fallback (runs if crt.sh completely fails or returns empty)
    if (subdomainsSet.size === 0) {
        try {
            const data = await fetchWithRetry(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, 2, 10000);
            if (Array.isArray(data)) {
                for (const item of data) {
                    if (!item.dns_names) continue;
                    for (let name of item.dns_names) {
                        name = name.toLowerCase().replace(/^\*\./, '').trim();
                        if (name && name.endsWith(domain) && name !== domain) {
                            subdomainsSet.add(name);
                        }
                    }
                }
            }
        } catch (err) {
            console.error('[fetchSubdomainsFromCrtSh] Certspotter fallback failed:', err);
        }
    }

    return Array.from(subdomainsSet);
}

// ---------------------------------------------------------------------------
// Parallel DNS and HTTP Pre-Filtering Helpers
// ---------------------------------------------------------------------------
async function processInBatches<T, R>(
    items: T[],
    batchSize: number,
    fn: (item: T) => Promise<R>
): Promise<R[]> {
    const results: R[] = [];
    for (let i = 0; i < items.length; i += batchSize) {
        const batch = items.slice(i, i + batchSize);
        const batchResults = await Promise.all(batch.map(fn));
        results.push(...batchResults);
    }
    return results;
}

function isSuspiciousSubdomain(cname: string | null, ipAddresses: string[], httpStatus: number | null): boolean {
    if (!cname && ipAddresses.length === 0 && httpStatus === null) {
        // Completely dead and no CNAME – not resolvable, no dangling record
        return false;
    }
    if (cname) {
        // Points to known cloud provider (always suspicious)
        if (matchesCloudProvider(cname)) return true;
        // Dangling entry (has CNAME but no IPs or HTTP error/unreachable)
        if (ipAddresses.length === 0 || httpStatus === 404 || httpStatus === 410 || httpStatus === null) {
            return true;
        }
    }
    // If no CNAME but returns 404 or 410 or is unreachable, let the agent inspect
    if (httpStatus === 404 || httpStatus === 410 || httpStatus === null) {
        return true;
    }
    return false;
}

async function probeSubdomainQuick(
    subdomain: string
): Promise<SubdomainResult & { ipAddresses: string[]; isSuspicious: boolean }> {
    let cname: string | null = null;
    let ipAddresses: string[] = [];
    let httpStatus: number | null = null;
    let error: string | null = null;

    // 1. Resolve CNAME
    try {
        const cnames = await dns.promises.resolveCname(subdomain);
        cname = cnames[0] ?? null;
    } catch (err: any) {
        // Ignore resolution error
    }

    // 2. Resolve A records
    try {
        ipAddresses = await dns.promises.resolve4(subdomain);
    } catch (err: any) {
        error = err.message || String(err);
    }

    // 3. Probe HTTP status
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        const response = await fetch(`http://${subdomain}`, {
            method: 'GET',
            signal: controller.signal,
            redirect: 'follow',
        });
        clearTimeout(timeout);
        httpStatus = response.status;
    } catch (err: any) {
        // Unreachable
    }

    const isSuspicious = isSuspiciousSubdomain(cname, ipAddresses, httpStatus);

    return {
        subdomain,
        cname,
        ipAddresses,
        httpStatus,
        error,
        isSuspicious,
    };
}


// ---------------------------------------------------------------------------
// Cloud provider patterns for takeover detection
// ---------------------------------------------------------------------------
const CLOUD_TAKEOVER_PATTERNS: RegExp[] = [
    /\.wordpress\.com$/i,
    /\.github\.io$/i,
    /\.vercel\.app$/i,
    /\.vercel-dns\.com$/i, // <-- Add this to catch custom domain CNAMEs
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
    /\.edgekey\.net$/i,   // Akamai Edge Suite
    /\.edgesuite\.net$/i,  // Akamai
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
// TOOL DEFINITIONS — OpenAI Function Calling Format
// ---------------------------------------------------------------------------
const AGENT_TOOLS: OpenAI.Chat.ChatCompletionTool[] = [
    {
        type: 'function',
        function: {
            name: 'resolve_cname',
            description: 'Resolve the CNAME record for a subdomain. Returns the canonical name if it exists, or null if no CNAME record is available.',
            parameters: {
                type: 'object',
                properties: {
                    subdomain: {
                        type: 'string',
                        description: 'The subdomain to resolve (e.g., "blog.example.com")',
                    },
                },
                required: ['subdomain'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'resolve_a_record',
            description: 'Resolve the A record (IPv4 addresses) for a subdomain. Returns an array of IP addresses or null if resolution failed.',
            parameters: {
                type: 'object',
                properties: {
                    subdomain: {
                        type: 'string',
                        description: 'The subdomain to resolve (e.g., "api.example.com")',
                    },
                },
                required: ['subdomain'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'probe_http_status',
            description: 'Probe the HTTP status code for a subdomain. Returns the HTTP status code (e.g., 200, 404) or null if unreachable.',
            parameters: {
                type: 'object',
                properties: {
                    subdomain: {
                        type: 'string',
                        description: 'The subdomain to probe (e.g., "staging.example.com")',
                    },
                },
                required: ['subdomain'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'check_cloud_provider',
            description: 'Check if a CNAME target points to a known cloud provider susceptible to takeover (e.g., GitHub Pages, Vercel, S3). Returns the provider pattern if matched.',
            parameters: {
                type: 'object',
                properties: {
                    cname: {
                        type: 'string',
                        description: 'The CNAME record to check (e.g., "myapp.github.io")',
                    },
                },
                required: ['cname'],
            },
        },
    },


    {
        type: 'function',
        function: {
            name: 'analyze_subdomain_takeover',
            description: 'Perform AI-powered analysis to determine if a subdomain is vulnerable to takeover. Returns structured vulnerability assessment.',
            parameters: {
                type: 'object',
                properties: {
                    subdomain: {
                        type: 'string',
                        description: 'The subdomain to analyze',
                    },
                    cname: {
                        type: ['string', 'null'], // <-- Updated
                        description: 'The CNAME record, if any',
                    },
                    http_status: {
                        type: ['number', 'null'], // <-- Updated
                        description: 'The HTTP status code from probing',
                    },
                    ip_addresses: {
                        type: 'array',
                        items: { type: 'string' },
                        description: 'Resolved A records',
                    },
                },
                required: ['subdomain'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'generate_remediation_report',
            description: 'Generate a professional Markdown remediation report for a confirmed vulnerability.',
            parameters: {
                type: 'object',
                properties: {
                    subdomain: {
                        type: 'string',
                        description: 'The vulnerable subdomain',
                    },
                    cname: {
                        type: ['string', 'null'], // <-- Updated
                        description: 'The dangling CNAME',
                    },
                    http_status: {
                        type: ['number', 'null'], // <-- Updated
                        description: 'HTTP status code',
                    },
                    confidence: {
                        type: 'string',
                        enum: ['High', 'Medium', 'Low'],
                        description: 'Confidence level of the vulnerability',
                    },
                    reasoning: {
                        type: 'string',
                        description: 'AI reasoning for the vulnerability',
                    },
                    signature_found: {
                        type: 'string',
                        description: 'Signature that indicates the vulnerability',
                    },
                },
                required: ['subdomain', 'cname', 'http_status', 'confidence', 'reasoning', 'signature_found'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'mark_subdomain_safe',
            description: 'Mark a subdomain as safe after analysis determines no takeover risk. Use when the subdomain has been fully analyzed and cleared.',
            parameters: {
                type: 'object',
                properties: {
                    subdomain: {
                        type: 'string',
                        description: 'The subdomain to mark as safe',
                    },
                    reason: {
                        type: 'string',
                        description: 'Brief explanation of why it is safe',
                    },
                },
                required: ['subdomain', 'reason'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'confirm_vulnerability',
            description: 'Confirm and record a found vulnerability. This saves the vulnerability to the database with all evidence.',
            parameters: {
                type: 'object',
                properties: {
                    subdomain: {
                        type: 'string',
                        description: 'The vulnerable subdomain',
                    },
                    severity: {
                        type: 'string',
                        enum: ['Critical', 'High', 'Medium', 'Low'],
                        description: 'Severity level',
                    },
                    evidence: {
                        type: 'string',
                        description: 'Full remediation report as Markdown',
                    },
                },
                required: ['subdomain', 'severity', 'evidence'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'select_next_subdomain',
            description: 'Select the next subdomain to analyze from the discovered list. Returns the subdomain name or indicates completion.',
            parameters: {
                type: 'object',
                properties: {
                    reasoning: {
                        type: 'string',
                        description: 'Why this subdomain was selected (e.g., "has interesting CNAME pattern")',
                    },
                },
                required: ['reasoning'],
            },
        },
    },
    {
        type: 'function',
        function: {
            name: 'finalize_analysis',
            description: 'Signal that the agent has completed analysis of all subdomains. Call when no more work is needed.',
            parameters: {
                type: 'object',
                properties: {
                    summary: {
                        type: 'string',
                        description: 'Final summary of findings',
                    },
                    vulnerabilities_found: {
                        type: 'number',
                        description: 'Total number of vulnerabilities found',
                    },
                },
                required: ['summary', 'vulnerabilities_found'],
            },
        },
    },
];

// ---------------------------------------------------------------------------
// TOOL EXECUTORS — Actual implementation of each tool
// ---------------------------------------------------------------------------
async function executeTool(
    toolName: string,
    args: Record<string, unknown>,
    context: AgentContext
): Promise<string> {
    const targetId = context.targetId;

    switch (toolName) {
        case 'resolve_cname': {
            const subdomain = args.subdomain as string;
            await logToolCall(targetId, 'resolve_cname', subdomain, '...');

            let probe = context.probedSubdomains.get(subdomain);
            if (probe && probe.cname !== undefined) {
                const result = probe.cname ? `CNAME → ${probe.cname}` : 'No CNAME record found';
                await logToolResult(targetId, `(Cached) ${result}`);
                return JSON.stringify({ success: true, cname: probe.cname, subdomain });
            }

            try {
                const cnameRecords = await dns.promises.resolveCname(subdomain);
                const cname = cnameRecords[0] ?? null;

                if (!probe) {
                    probe = { subdomain, cname: null, ipAddresses: [], httpStatus: null, error: null };
                    context.probedSubdomains.set(subdomain, probe);
                }
                probe.cname = cname;

                const result = cname ? `CNAME → ${cname}` : 'No CNAME record found';
                await logToolResult(targetId, result);
                return JSON.stringify({ success: true, cname, subdomain });
            } catch (err) {
                const result = 'No CNAME record found (NXDOMAIN or no data)';
                await logToolResult(targetId, result);
                return JSON.stringify({ success: true, cname: null, subdomain, note: result });
            }
        }

        case 'resolve_a_record': {
            const subdomain = args.subdomain as string;
            await logToolCall(targetId, 'resolve_a_record', subdomain, '...');

            let probe = context.probedSubdomains.get(subdomain);
            if (probe && probe.ipAddresses && probe.ipAddresses.length > 0) {
                const result = `A-records: ${probe.ipAddresses.join(', ')}`;
                await logToolResult(targetId, `(Cached) ${result}`);
                return JSON.stringify({ success: true, ipAddresses: probe.ipAddresses, subdomain });
            }

            try {
                const ipAddresses = await dns.promises.resolve4(subdomain);

                if (!probe) {
                    probe = { subdomain, cname: null, ipAddresses: [], httpStatus: null, error: null };
                    context.probedSubdomains.set(subdomain, probe);
                }
                probe.ipAddresses = ipAddresses;

                const result = `A-records: ${ipAddresses.join(', ')}`;
                await logToolResult(targetId, result);
                return JSON.stringify({ success: true, ipAddresses, subdomain });
            } catch (err) {
                const result = 'No A-record found';
                await logToolResult(targetId, result);
                return JSON.stringify({ success: true, ipAddresses: [], subdomain, note: result });
            }
        }

        case 'probe_http_status': {
            const subdomain = args.subdomain as string;
            await logToolCall(targetId, 'probe_http_status', subdomain, '...');

            let probe = context.probedSubdomains.get(subdomain);
            if (probe && (probe.httpStatus !== null || probe.error !== null)) {
                const result = probe.httpStatus ? `HTTP ${probe.httpStatus}` : 'HTTP unreachable (cached)';
                await logToolResult(targetId, `(Cached) ${result}`);
                return JSON.stringify({ success: true, http_status: probe.httpStatus, subdomain, note: probe.error || 'HTTP unreachable (cached)' });
            }

            try {
                const controller = new AbortController();
                const timeout = setTimeout(() => controller.abort(), 5000);
                const response = await fetch(`http://${subdomain}`, {
                    method: 'GET',
                    signal: controller.signal,
                    redirect: 'follow',
                });
                clearTimeout(timeout);

                const httpStatus = response.status;

                if (!probe) {
                    probe = { subdomain, cname: null, ipAddresses: [], httpStatus: null, error: null };
                    context.probedSubdomains.set(subdomain, probe);
                }
                probe.httpStatus = httpStatus;

                // Insert to database
                await getSupabase().from('subdomains').upsert({
                    target_id: targetId,
                    subdomain,
                    cname: probe.cname,
                    http_status: httpStatus,
                    live_status: httpStatus < 500 ? 'live' : 'unknown',
                }, { onConflict: 'target_id,subdomain' });

                const result = `HTTP ${httpStatus}`;
                await logToolResult(targetId, result);
                return JSON.stringify({ success: true, http_status: httpStatus, subdomain });
            } catch (err) {
                const result = 'HTTP unreachable (connection refused or timed out)';

                if (!probe) {
                    probe = { subdomain, cname: null, ipAddresses: [], httpStatus: null, error: null };
                    context.probedSubdomains.set(subdomain, probe);
                }
                probe.error = result;

                await logToolResult(targetId, result);
                return JSON.stringify({ success: true, http_status: null, subdomain, note: result, cname: probe?.cname });
            }
        }

        case 'check_cloud_provider': {
            const cname = args.cname as string;
            await logToolCall(targetId, 'check_cloud_provider', cname, '...');

            const match = matchesCloudProvider(cname);
            const result = match ? `MATCH: ${match} is a known takeover-vulnerable provider` : 'Not a known cloud provider pattern';

            await logToolResult(targetId, result);
            return JSON.stringify({ success: true, is_cloud_provider: !!match, provider: match, cname });
        }

        case 'analyze_subdomain_takeover': {
            const subdomain = args.subdomain as string;
            const cname = args.cname as string | null;
            const httpStatus = args.http_status as number | null;
            const ipAddresses = (args.ip_addresses as string[]) ?? [];

            await logToolCall(targetId, 'analyze_subdomain_takeover', subdomain, '...');

            const prompt = `You are an expert Automated Bug Bounty Agent performing subdomain takeover analysis.

Analyze the following live asset data collected from real DNS and HTTP reconnaissance:

  Subdomain   : ${subdomain}
  CNAME Record: ${cname ?? 'None'}
  A-Records   : ${ipAddresses.length > 0 ? ipAddresses.join(', ') : 'None'}
  HTTP Status : ${httpStatus ?? 'Unreachable / Timed-Out'}

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
                const completion = await getAiClient().chat.completions.create({
                    model: REACT_MODEL,
                    messages: [{ role: 'user', content: prompt }],
                    response_format: { type: 'json_object' },
                    temperature: 0.1,
                });

                const rawContent = completion.choices[0]?.message?.content ?? '{}';
                const analysis = TakeoverAnalysisSchema.parse(JSON.parse(rawContent));

                context.analyzedSubdomains.add(subdomain);

                const result = `is_vulnerable=${analysis.is_vulnerable}, confidence=${analysis.confidence}`;
                await logToolResult(targetId, `${result}\nReasoning: ${analysis.reasoning}`);

                return JSON.stringify({ success: true, analysis, subdomain });
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                await logToolResult(targetId, `Analysis failed: ${msg}`);
                return JSON.stringify({ success: false, error: msg, subdomain });
            }
        }

        case 'generate_remediation_report': {
            const subdomain = args.subdomain as string;
            const cname = args.cname as string;
            const httpStatus = args.http_status as number | null;
            const confidence = args.confidence as string;
            const reasoning = args.reasoning as string;
            const signatureFound = args.signature_found as string;

            await logToolCall(targetId, 'generate_remediation_report', subdomain, '...');

            const prompt = `You are a senior application security engineer writing a professional bug bounty vulnerability report.

The following subdomain takeover vulnerability has been confirmed by an automated reconnaissance agent:

  Target Subdomain : ${subdomain}
  Dangling CNAME   : ${cname ?? 'N/A'}
  HTTP Status      : ${httpStatus ?? 'Unreachable'}
  Confidence Level : ${confidence}
  Agent Reasoning  : ${reasoning}
  Signature Found  : ${signatureFound}

Generate a COMPLETE, professional, copy-pasteable Markdown security report with the following sections:

# Subdomain Takeover — ${subdomain}

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
                const completion = await getAiClient().chat.completions.create({
                    model: REACT_MODEL,
                    messages: [{ role: 'user', content: prompt }],
                    temperature: 0.3,
                    max_tokens: 2048,
                });

                const report = completion.choices[0]?.message?.content?.trim() ?? `# Report Generation Failed\n\nThe AI model did not return content for ${subdomain}.`;

                await logToolResult(targetId, `Generated ${report.length} character Markdown report`);
                return JSON.stringify({ success: true, report, subdomain });
            } catch (err) {
                const msg = err instanceof Error ? err.message : String(err);
                await logToolResult(targetId, `Report generation failed: ${msg}`);
                return JSON.stringify({ success: false, error: msg, subdomain });
            }
        }

        case 'mark_subdomain_safe': {
            const subdomain = args.subdomain as string;
            const reason = args.reason as string;

            context.analyzedSubdomains.add(subdomain);

            await logToolCall(targetId, 'mark_subdomain_safe', subdomain, reason);
            const result = `Marked safe: ${reason}`;
            await logToolResult(targetId, result);
            return JSON.stringify({ success: true, subdomain, marked_safe: true });
        }

        case 'confirm_vulnerability': {
            const subdomain = args.subdomain as string;
            const severity = args.severity as string;
            const evidence = args.evidence as string;

            await logToolCall(targetId, 'confirm_vulnerability', subdomain, `severity=${severity}`);

            const { data: subRow } = await getSupabase()
                .from('subdomains')
                .select('id')
                .eq('target_id', targetId)
                .eq('subdomain', subdomain)
                .maybeSingle();

            await getSupabase().from('vulnerabilities').insert({
                target_id: targetId,
                subdomain_id: subRow?.id ?? null,
                vuln_type: 'Subdomain Takeover',
                severity,
                evidence,
            });

            await logToolResult(targetId, `VULNERABILITY CONFIRMED: ${subdomain} saved to database`);
            return JSON.stringify({ success: true, subdomain, severity });
        }

        case 'select_next_subdomain': {
            const reasoning = args.reasoning as string;

            await logToolCall(targetId, 'select_next_subdomain', '', reasoning);

            // Find next unanalyzed subdomain
            const unanalyzed = context.discoveredSubdomains.filter(s => !context.analyzedSubdomains.has(s));
            const nextSubdomain = unanalyzed[0] ?? null;

            if (nextSubdomain) {
                context.currentFocus = nextSubdomain;
                await logToolResult(targetId, `Selected ${nextSubdomain} for analysis`);
                return JSON.stringify({ success: true, subdomain: nextSubdomain, remaining: unanalyzed.length - 1 });
            } else {
                await logToolResult(targetId, 'No more subdomains to analyze');
                return JSON.stringify({ success: true, subdomain: null, remaining: 0, message: 'All subdomains have been analyzed' });
            }
        }

        case 'finalize_analysis': {
            const summary = args.summary as string;
            const vulnerabilitiesFound = args.vulnerabilities_found as number;

            await logToolCall(targetId, 'finalize_analysis', '', `vulns=${vulnerabilitiesFound}`);

            await logAgentThought(targetId, 'Completed', summary, vulnerabilitiesFound > 0 ? 'warning' : 'info');
            await getSupabase().from('targets').update({ status: 'completed' }).eq('id', targetId);

            return JSON.stringify({ success: true, summary, vulnerabilities_found: vulnerabilitiesFound, target_id: targetId });
        }

        default:
            return JSON.stringify({ success: false, error: `Unknown tool: ${toolName}` });
    }
}

// ---------------------------------------------------------------------------
// REAct AGENT LOOP — Main orchestration
// ---------------------------------------------------------------------------
const MAX_ITERATIONS = 60;

async function runReActAgent(context: AgentContext): Promise<void> {
    const targetId = context.targetId;
    const systemPrompt = `You are BountyWire Agent — an autonomous security reconnaissance agent specialized in subdomain takeover detection.

Your mission: Analyze discovered subdomains and identify takeover vulnerabilities using a reasoning-action cycle.

## AVAILABLE TOOLS
- resolve_cname: Get CNAME record for a subdomain
- resolve_a_record: Get A records (IP addresses) for a subdomain
- probe_http_status: Check HTTP response code
- check_cloud_provider: Test if CNAME points to a takeover-vulnerable platform
- analyze_subdomain_takeover: AI-powered vulnerability assessment
- generate_remediation_report: Create professional security report
- mark_subdomain_safe: Record that a subdomain is not vulnerable
- confirm_vulnerability: Save a confirmed vulnerability to the database
- select_next_subdomain: Pick the next target for analysis
- finalize_analysis: Signal completion of all work

## REASONING PROCESS
For each subdomain, follow this workflow:
1. THINK: What information do I need?
2. ACT: Call the appropriate tool
3. OBSERVE: Analyze the result
4. Repeat until confident about vulnerability status

## VULNERABILITY INDICATORS
- CNAME points to cloud provider (github.io, vercel.app, s3.amazonaws.com, etc.)
- HTTP returns 404, 410, or is unreachable
- CNAME resource appears deprovisioned

## CONSTRAINTS
- You have ${MAX_ITERATIONS} iterations max
- Start by selecting a subdomain, then probe it methodically
- Always call finalize_analysis when done

## CURRENT STATE
Domain: ${context.domain}
Discovered Subdomains: ${context.discoveredSubdomains.length}
Already Analyzed: ${context.analyzedSubdomains.size}

Begin by selecting your first subdomain to analyze.`;

    const messages: OpenAI.Chat.ChatCompletionMessageParam[] = [
        { role: 'system', content: systemPrompt },
    ];

    for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
        await logAgentReasoning(targetId, `Starting iteration ${iteration + 1}/${MAX_ITERATIONS}...`);

        try {
            const completion = await getAiClient().chat.completions.create({
                model: REACT_MODEL,
                messages,
                tools: AGENT_TOOLS,
                tool_choice: 'auto',
                temperature: 0.2,
            });

            const assistantMessage = completion.choices[0]?.message;
            if (!assistantMessage) break;

            // Log any reasoning content
            if (assistantMessage.content) {
                await logAgentReasoning(targetId, assistantMessage.content);
            }

            // Add assistant message to history
            messages.push(assistantMessage);

            // Check if we have tool calls
            const toolCalls = assistantMessage.tool_calls;
            if (!toolCalls || toolCalls.length === 0) {
                // No tool calls — agent is thinking or done
                if (assistantMessage.content?.includes('finalize') || iteration >= MAX_ITERATIONS - 1) {
                    await logAgentReasoning(targetId, 'Agent signaled completion or reached iteration limit.');
                    break;
                }
                continue;
            }

            // Process each tool call
            for (const toolCall of toolCalls) {
                // Type guard for function tool calls
                if (toolCall.type !== 'function') continue;
                const toolName = toolCall.function.name;
                const toolArgs = JSON.parse(toolCall.function.arguments);

                // Execute the tool
                const toolResult = await executeTool(toolName, toolArgs, context);

                // Add tool result to message history
                messages.push({
                    role: 'tool',
                    tool_call_id: toolCall.id,
                    content: toolResult,
                });

                // Check for finalization
                if (toolName === 'finalize_analysis') {
                    const result = JSON.parse(toolResult);
                    context.vulnerabilities = context.vulnerabilities.slice(0, result.vulnerabilities_found);
                    return;
                }
            }
        } catch (err) {
            const msg = err instanceof Error ? err.message : String(err);
            await logAgentThought(targetId, 'Agent Error', `Error in iteration ${iteration + 1}: ${msg}`, 'warning');
            break;
        }
    }

    // If we exit loop without finalize, force completion
    await logAgentThought(
        targetId,
        'Completed',
        `Agent analysis complete after ${MAX_ITERATIONS} iterations. Found ${context.vulnerabilities.length} vulnerabilities.`
    );
    await getSupabase().from('targets').update({ status: 'completed' }).eq('id', targetId);
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
        const { data: targetData, error: targetError } = await getSupabase()
            .from('targets')
            .insert({ domain, status: 'scanning' })
            .select()
            .single();

        if (targetError) throw new Error(`Failed to create target: ${targetError.message}`);
        targetId = targetData.id as string;

        // Perform the scan asynchronously using Next.js after()
        after(async () => {
            try {
                await logAgentThought(
                    targetId!,
                    'Initialization',
                    `BountyWire ReAct Agent initialized. Target: ${domain}. Agent will autonomously reason and act to detect takeover vulnerabilities.`
                );

                // -----------------------------------------------------------------------
                // Step 1: Discovery Phase
                // -----------------------------------------------------------------------
                await logAgentThought(
                    targetId!,
                    'Discovery',
                    `Phase 1: Discovering subdomains via Certificate Transparency logs...`
                );

                let discoveredSubdomains = await fetchSubdomainsFromCrtSh(domain);

                // Terminate cleanly if no subdomains are found naturally
                if (discoveredSubdomains.length === 0) {
                    await logAgentThought(
                        targetId!,
                        'Completed',
                        `No subdomains discovered for ${domain}. Terminating analysis.`,
                        'warning'
                    );
                    await getSupabase().from('targets').update({ status: 'completed' }).eq('id', targetId);
                    return;
                }

                // Cap at 40 subdomains for the pre-filtering phase
                const maxPreFilterSubdomains = 40;
                const truncated = discoveredSubdomains.length > maxPreFilterSubdomains;
                if (truncated) {
                    discoveredSubdomains = discoveredSubdomains.slice(0, maxPreFilterSubdomains);
                }

                await logAgentThought(
                    targetId!,
                    'Discovery',
                    `Discovered ${discoveredSubdomains.length} subdomains. Running parallel DNS/HTTP pre-filtering step...`
                );

                // Run DNS & HTTP pre-filtering in parallel batches (concurrency: 5)
                const preFilterResults = await processInBatches(discoveredSubdomains, 5, probeSubdomainQuick);

                // Save all results to database and update UI
                for (const res of preFilterResults) {
                    try {
                        await getSupabase().from('subdomains').insert({
                            target_id: targetId!,
                            subdomain: res.subdomain,
                            cname: res.cname,
                            http_status: res.httpStatus,
                            live_status: res.httpStatus !== null && res.httpStatus < 500 ? 'live' : 'unknown',
                        });
                    } catch {
                        // In case of conflict, upsert to update values
                        try {
                            await getSupabase().from('subdomains').upsert({
                                target_id: targetId!,
                                subdomain: res.subdomain,
                                cname: res.cname,
                                http_status: res.httpStatus,
                                live_status: res.httpStatus !== null && res.httpStatus < 500 ? 'live' : 'unknown',
                            }, { onConflict: 'target_id,subdomain' });
                        } catch (upsertErr) {
                            console.error('Failed to upsert subdomain result:', upsertErr);
                        }
                    }
                }

                // Filter to find suspicious subdomains
                const suspiciousResults = preFilterResults.filter(res => res.isSuspicious);
                const suspiciousSubdomains = suspiciousResults.map(res => res.subdomain);

                await logAgentThought(
                    targetId!,
                    'Discovery',
                    `Pre-filtering complete. Found ${suspiciousSubdomains.length} subdomains exhibiting suspicious footprints (404s, dangling entries).`
                );

                // If no subdomains are suspicious, we terminate early!
                if (suspiciousSubdomains.length === 0) {
                    await logAgentThought(
                        targetId!,
                        'Completed',
                        `All discovered subdomains cleared during pre-filtering (no suspicious footprints found). Terminating scan.`,
                        'info'
                    );
                    await getSupabase().from('targets').update({ status: 'completed' }).eq('id', targetId);
                    return;
                }

                // -----------------------------------------------------------------------
                // Step 2: Initialize Agent Context with pre-populated probe results
                // -----------------------------------------------------------------------
                const probedMap = new Map<string, SubdomainResult>();
                for (const res of preFilterResults) {
                    probedMap.set(res.subdomain, {
                        subdomain: res.subdomain,
                        cname: res.cname,
                        ipAddresses: res.ipAddresses,
                        httpStatus: res.httpStatus,
                        error: res.error,
                    });
                }

                const context: AgentContext = {
                    targetId: targetId!,
                    domain,
                    discoveredSubdomains: suspiciousSubdomains,
                    probedSubdomains: probedMap,
                    analyzedSubdomains: new Set(),
                    vulnerabilities: [],
                    currentFocus: null,
                };

                // -----------------------------------------------------------------------
                // Step 3: Run the Autonomous ReAct Agent
                // -----------------------------------------------------------------------
                await logAgentThought(
                    targetId!,
                    'Agent Start',
                    `Activating autonomous reasoning loop. Agent will analyze ${suspiciousSubdomains.length} suspicious subdomains using pre-populated DNS/HTTP cache.`
                );

                await runReActAgent(context);

            } catch (error: unknown) {
                const msg = error instanceof Error ? error.message : String(error);
                console.error('[POST /api/scan background task] Fatal agent exception:', msg);
                if (targetId) {
                    await logAgentThought(targetId, 'Failed', `Critical engine exception: ${msg}`, 'critical');
                    await getSupabase().from('targets').update({ status: 'failed' }).eq('id', targetId);
                }
            }
        });

        // -----------------------------------------------------------------------
        // Step 4: Return Target ID immediately to the client
        // -----------------------------------------------------------------------
        return NextResponse.json({
            success: true,
            target_id: targetId,
        });

    } catch (error: unknown) {
        const msg = error instanceof Error ? error.message : String(error);
        console.error('[POST /api/scan] Fatal exception:', msg);
        if (targetId) {
            await logAgentThought(targetId, 'Failed', `Critical engine exception: ${msg}`, 'critical');
            await getSupabase().from('targets').update({ status: 'failed' }).eq('id', targetId);
        }
        return NextResponse.json({ error: msg }, { status: 500 });
    }
}
