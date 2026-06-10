import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import OpenAI from 'openai';
import { z } from 'zod';

// 1. Configure the Vercel function execution limit to the maximum 5-minute allowance
export const maxDuration = 300;

// Initialize Clients using Next.js Environment Variables
const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY! // Use backend service role key
);

const aiClient = new OpenAI({
    baseURL: "https://api.groq.com/openai/v1",
    apiKey: process.env.GROQ_API_KEY!,
});

// Zod Schema to force Groq into a strict JSON output structure
const TakeoverAnalysisSchema = z.object({
    is_vulnerable: z.boolean(),
    confidence: z.enum(['High', 'Medium', 'Low']),
    reasoning: z.string(),
    signature_found: z.string(),
});

// Helper to log thoughts to Supabase Realtime
async function logAgentThought(targetId: string, stepName: string, message: string, logLevel = 'info') {
    await supabase.from('agent_logs').insert({
        target_id: targetId,
        step_name: stepName,
        log_level: logLevel,
        message: message,
    });
}

export async function POST(request: Request) {
    let targetId: string | null = null;
    let domain = "";

    try {
        const body = await request.json();
        domain = body.domain?.trim().toLowerCase();

        if (!domain) {
            return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
        }

        // Step 1: Create initial Target record
        const { data: targetData, error: targetError } = await supabase
            .from('targets')
            .insert({ domain: domain, status: 'scanning' })
            .select()
            .single();

        if (targetError) throw targetError;
        targetId = targetData.id;

        // --- AGENT EXECUTION LOOP BEGINS ---
        await logAgentThought(targetId!, "Enumeration", `Starting passive subdomain enumeration for ${domain}...`);

        // Simulated Recon tool discovery
        const mockSubdomain = `dev-marketing.${domain}`;
        const mockCname = "unclaimed-bucket.wordpress.com";

        const { data: subData, error: subError } = await supabase
            .from('subdomains')
            .insert({
                target_id: targetId,
                subdomain: mockSubdomain,
                cname: mockCname,
                http_status: 404,
            })
            .select()
            .single();

        if (subError) throw subError;

        // Step 2: Prompt Engineering & Model Analysis Loop
        await logAgentThought(targetId!, "Analysis Loop", `Analyzing CNAME record: ${mockCname} for ${mockSubdomain}`);

        const prompt = `You are an expert Automated Bug Bounty Agent. Analyze this asset data:
    Subdomain: ${mockSubdomain}
    CNAME: ${mockCname}
    HTTP Status: 404

    Determine if this asset is vulnerable to a Subdomain Takeover.
    You must respond exclusively with a raw JSON object matching this schema structure:
    {
      "is_vulnerable": true or false,
      "confidence": "High" or "Medium" or "Low",
      "reasoning": "string text",
      "signature_found": "string text"
    }`;

        const completion = await aiClient.chat.completions.create({
            model: "openai/gpt-oss-20b",
            messages: [{ role: "user", content: prompt }],
            response_format: { type: "json_object" },
            temperature: 0.1,
        });

        const rawContent = completion.choices[0].message.content || "{}";
        const parsedAnalysis = TakeoverAnalysisSchema.parse(JSON.parse(rawContent));

        // Step 3: Action Escalation & Finalization
        if (parsedAnalysis.is_vulnerable) {
            await logAgentThought(
                targetId!,
                "Takeover Verification",
                `Vulnerability flagged with ${parsedAnalysis.confidence} confidence. Reasoning: ${parsedAnalysis.reasoning}`,
                "warning"
            );

            await supabase.from('vulnerabilities').insert({
                target_id: targetId,
                subdomain_id: subData.id,
                vuln_type: "Subdomain Takeover",
                severity: parsedAnalysis.confidence === "High" ? "High" : "Medium",
                evidence: `CNAME: ${mockCname} returning 404. Agent Notes: ${parsedAnalysis.reasoning}`,
            });
        }

        await logAgentThought(targetId!, "Completed", `Finished evaluation loop for ${domain}.`);

        // Update master target status
        await supabase.from('targets').update({ status: 'completed' }).eq('id', targetId);

        return NextResponse.json({ success: true, target_id: targetId });

    } catch (error: any) {
        console.error("Agent Engine Error:", error);
        if (targetId) {
            await logAgentThought(targetId, "Failed", `Critical engine exception: ${error.message}`, "critical");
            await supabase.from('targets').update({ status: 'failed' }).eq('id', targetId);
        }
        return NextResponse.json({ error: error.message }, { status: 500 });
    }
}