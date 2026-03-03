import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import { KnowledgeBasePage } from "./knowledge-base.client";
import { useApi } from "@/shared/lib/hooks/useApi";

jest.mock("@/shared/lib/hooks/useApi", () => ({
  useApi: jest.fn(),
}));

const mockedUseApi = useApi as jest.Mock;

describe("KnowledgeBasePage", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("loads examples, switches to logs, and opens log details", async () => {
    const get = jest.fn().mockImplementation((url: string) => {
      if (url.startsWith("/triage-kb/examples")) {
        return Promise.resolve({
          items: [
            {
              id: "example-1",
              tenant_id: "singletenant",
              scope: "alert",
              proposed_severity: "warning",
              reason: "Example reason",
              alert_text: "Example alert",
              created_by: "tester@keep.dev",
              created_at: "2026-03-03T11:00:00Z",
              updated_at: "2026-03-03T11:00:00Z",
              current_severity: "info",
              alert_id: "a-1",
              incident_id: null,
              fingerprint: "fp-1",
              source: ["mailgun"],
              provider_id: "provider-1",
              incident_alerts: [],
              metadata: {},
            },
          ],
          count: 1,
        });
      }
      if (url.startsWith("/triage-kb/logs?")) {
        return Promise.resolve({
          items: [
            {
              id: "run-1",
              tenant_id: "singletenant",
              incident_id: "inc-1",
              mode: "single",
              status: "success",
              recommended_severity: "warning",
              reason: "Matched warning example",
              error_message: null,
              created_at: "2026-03-03T11:10:00Z",
              completed_at: "2026-03-03T11:10:01Z",
            },
          ],
          count: 1,
        });
      }
      if (url === "/triage-kb/logs/run-1") {
        return Promise.resolve({
          id: "run-1",
          tenant_id: "singletenant",
          incident_id: "inc-1",
          mode: "single",
          status: "success",
          recommended_severity: "warning",
          reason: "Matched warning example",
          error_message: null,
          created_at: "2026-03-03T11:10:00Z",
          completed_at: "2026-03-03T11:10:01Z",
          request_payload: { mode: "single" },
          retrieval_trace: [{ mode: "single", candidates: [] }],
          llm_trace: [{ normalized_response: { recommended_severity: "warning" } }],
          response_payload: {
            incident_id: "inc-1",
            recommended_severity: "warning",
            reason: "Matched warning example",
            validated_fingerprints: ["fp-1"],
            matched_rules: [],
          },
        });
      }
      return Promise.reject(new Error(`Unhandled URL in test: ${url}`));
    });

    mockedUseApi.mockReturnValue({
      get,
      post: jest.fn(),
      put: jest.fn(),
      delete: jest.fn(),
    });

    render(<KnowledgeBasePage />);

    await waitFor(() => {
      expect(get).toHaveBeenCalledWith(expect.stringContaining("/triage-kb/examples"));
    });

    expect(await screen.findByText("Triage Knowledge Base")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /LLM Logs/i }));

    await waitFor(() => {
      expect(get).toHaveBeenCalledWith(expect.stringContaining("/triage-kb/logs?"));
    });

    fireEvent.click(await screen.findByRole("button", { name: "View" }));

    await waitFor(() => {
      expect(get).toHaveBeenCalledWith("/triage-kb/logs/run-1");
    });

    expect(await screen.findByText("LLM Trace")).toBeInTheDocument();
  });
});
