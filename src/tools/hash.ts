import { z } from "zod";
import { createDVQuery, getDVQueryStatus, getDVEvents } from "../client/rest.js";
import { formatTimeAgo, truncatePath } from "../utils.js";

export const hashLookupSchema = z.object({
  hash: z
    .string()
    .describe("SHA1 (40 chars) or SHA256 (64 chars) hash to hunt across the fleet via Deep Visibility"),
});

function summarizeHashEvent(e: Record<string, any>): string {
  const time = e.eventTime ? formatTimeAgo(e.eventTime) : "unknown";
  const type = e.eventType || "Unknown";
  const process = e.processName || "N/A";
  const agent = e.agentName || "Unknown";
  const user = e.processUser || e.user || "";

  let details = "";
  if (e.filePath) details += ` | ${truncatePath(e.filePath, 60)}`;
  if (e.processCommandLine) details += ` | cmd: ${e.processCommandLine.slice(0, 80)}`;
  if (user) details += ` | ${user}`;

  return `• ${agent} | ${type} | ${process} | ${time}${details}`;
}

export async function handleHashLookup(
  params: z.infer<typeof hashLookupSchema>
) {
  try {
    const hashLength = params.hash.length;
    if (hashLength !== 40 && hashLength !== 64) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Invalid hash format. Expected SHA1 (40 chars) or SHA256 (64 chars), got ${hashLength} chars`,
          },
        ],
        isError: true,
      };
    }
    if (!/^[a-fA-F0-9]+$/.test(params.hash)) {
      return {
        content: [
          {
            type: "text" as const,
            text: "Invalid hash format. Hash must be hexadecimal characters only.",
          },
        ],
        isError: true,
      };
    }

    const hashField = hashLength === 64 ? "SHA256" : "SHA1";
    const dvQuery = `${hashField} = "${params.hash}"`;

    // Last 14 days
    const toDate = new Date().toISOString();
    const fromDate = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString();

    // Retry query creation on 409 (S1 limits concurrent DV queries per token)
    let result;
    let createAttempts = 0;
    const maxCreateRetries = 6;

    while (createAttempts < maxCreateRetries) {
      try {
        result = await createDVQuery({
          query: dvQuery,
          fromDate,
          toDate,
        });
        break;
      } catch (createError) {
        const msg = createError instanceof Error ? createError.message : String(createError);
        if (msg.includes("409") && createAttempts < maxCreateRetries - 1) {
          createAttempts++;
          await new Promise((resolve) => setTimeout(resolve, 3000));
          continue;
        }
        throw createError;
      }
    }

    if (!result) {
      return {
        content: [
          {
            type: "text" as const,
            text: "DV query slot busy - another query is still processing. Try again shortly.",
          },
        ],
        isError: true,
      };
    }

    // Poll for completion
    let attempts = 0;
    const maxAttempts = 30;
    let status: { status: string; responseError?: string } = { status: "RUNNING" };

    while (attempts < maxAttempts) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      status = await getDVQueryStatus(result.queryId);
      if (status.status !== "RUNNING") break;
      attempts++;
    }

    if (status.status === "FAILED") {
      return {
        content: [
          {
            type: "text" as const,
            text: `DV hash query failed: ${status.responseError || "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }

    if (status.status === "RUNNING") {
      return {
        content: [
          {
            type: "text" as const,
            text: `Query still running after ${maxAttempts}s. Use s1_dv_get_events with queryId: ${result.queryId}`,
          },
        ],
      };
    }

    // Fetch events with 409 retry (S1 can report FINISHED before events are ready)
    let events;
    let fetchAttempts = 0;
    const maxFetchRetries = 5;

    while (fetchAttempts < maxFetchRetries) {
      try {
        events = await getDVEvents({
          queryId: result.queryId,
          limit: 50,
        });
        break;
      } catch (fetchError) {
        const msg = fetchError instanceof Error ? fetchError.message : String(fetchError);
        if (msg.includes("409") && fetchAttempts < maxFetchRetries - 1) {
          fetchAttempts++;
          await new Promise((resolve) => setTimeout(resolve, 2000));
          continue;
        }
        throw fetchError;
      }
    }

    if (!events) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Query completed but events not available after retries. Use s1_dv_get_events with queryId: ${result.queryId}`,
          },
        ],
      };
    }

    if (!events.data?.length) {
      return {
        content: [
          {
            type: "text" as const,
            text: `No activity found for ${hashField} ${params.hash} in the last 14 days.`,
          },
        ],
      };
    }

    // Deduplicate by agent to show fleet spread
    const agents = new Set(events.data.map((e: Record<string, any>) => e.agentName || "Unknown"));
    const header = `Hash ${hashField} ${params.hash}\nSeen on ${agents.size} endpoint(s) | ${events.data.length} event(s) in last 14 days:\n\n`;
    const summary = events.data.map(summarizeHashEvent).join("\n");
    const footer = events.pagination?.nextCursor
      ? `\n\n[More results - use s1_dv_get_events with queryId: ${result.queryId}, cursor: ${events.pagination.nextCursor}]`
      : "";

    return {
      content: [
        {
          type: "text" as const,
          text: header + summary + footer,
        },
      ],
    };
  } catch (error) {
    return {
      content: [
        {
          type: "text" as const,
          text: `Error hunting hash: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
}
