import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { IncidentProposeSeverityModal } from "./incident-propose-severity-modal";
import { IncidentDto } from "@/entities/incidents/model";
import { useApi } from "@/shared/lib/hooks/useApi";

const mockedUseApi = useApi as jest.Mock;

function buildIncident(overrides: Partial<IncidentDto> = {}): IncidentDto {
  return {
    id: "11111111-1111-1111-1111-111111111111",
    user_generated_name: "Incident test",
    ai_generated_name: "",
    user_summary: "summary",
    generated_summary: "",
    assignee: "",
    severity: "warning" as IncidentDto["severity"],
    status: "firing" as IncidentDto["status"],
    alerts_count: 1,
    alert_sources: ["mailgun"],
    services: [],
    creation_time: new Date(),
    is_candidate: false,
    rule_fingerprint: "",
    same_incident_in_the_past_id: "",
    following_incidents_ids: [],
    merged_into_incident_id: "",
    merged_by: "",
    merged_at: new Date(),
    fingerprint: "incident-fp",
    enrichments: {},
    resolve_on: "all_resolved",
    ...overrides,
  };
}

describe("IncidentProposeSeverityModal", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("creates a proposal and shows queued success state", async () => {
    const get = jest.fn().mockRejectedValue(new Error("404"));
    const post = jest.fn().mockResolvedValue({
      id: "proposal-1",
      incident_id: "11111111-1111-1111-1111-111111111111",
      incident_name: "Incident test",
      incident_status: "firing",
      current_severity: "warning",
      proposed_severity: "high",
      reason: "Multiple alert patterns indicate broader impact.",
      alerts_count: 2,
      created_by: "tester@keep.dev",
      created_at: "2026-02-27T10:00:00Z",
      sync_status: "pending",
      sync_status_reason: "Queued",
      deduplicated: false,
    });
    mockedUseApi.mockReturnValue({
      get,
      post,
      put: jest.fn(),
      delete: jest.fn(),
    });

    render(
      <IncidentProposeSeverityModal
        incident={buildIncident()}
        isOpen={true}
        onClose={jest.fn()}
      />
    );

    await waitFor(() => {
      expect(get).toHaveBeenCalled();
    });

    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "Multiple alert patterns indicate broader impact." },
    });
    fireEvent.change(screen.getByLabelText("Proposed severity"), {
      target: { value: "high" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save example" }));

    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        "/incidents/11111111-1111-1111-1111-111111111111/propose-severity",
        {
          proposed_severity: "high",
          reason: "Multiple alert patterns indicate broader impact.",
        }
      );
    });
    expect(
      await screen.findByText("Example saved. Sync queued.")
    ).toBeInTheDocument();
  });

  it("loads existing proposal and updates it", async () => {
    const get = jest.fn().mockResolvedValue({
      id: "proposal-1",
      incident_id: "11111111-1111-1111-1111-111111111111",
      incident_name: "Incident test",
      incident_status: "firing",
      current_severity: "warning",
      proposed_severity: "warning",
      reason: "Initial reason",
      alerts_count: 1,
      created_by: "tester@keep.dev",
      created_at: "2026-02-27T10:00:00Z",
      sync_status: "synced",
      deduplicated: false,
    });
    const put = jest.fn().mockResolvedValue({
      id: "proposal-1",
      incident_id: "11111111-1111-1111-1111-111111111111",
      incident_name: "Incident test",
      incident_status: "firing",
      current_severity: "warning",
      proposed_severity: "critical",
      reason: "Updated reason",
      alerts_count: 1,
      created_by: "tester@keep.dev",
      created_at: "2026-02-27T10:00:00Z",
      updated_by: "tester@keep.dev",
      updated_at: "2026-02-27T11:00:00Z",
      sync_status: "synced",
      deduplicated: false,
    });
    mockedUseApi.mockReturnValue({
      get,
      post: jest.fn(),
      put,
      delete: jest.fn(),
    });

    render(
      <IncidentProposeSeverityModal
        incident={buildIncident()}
        isOpen={true}
        onClose={jest.fn()}
      />
    );

    await waitFor(() => {
      expect(get).toHaveBeenCalled();
    });
    expect(await screen.findByDisplayValue("Initial reason")).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "Updated reason" },
    });
    fireEvent.change(screen.getByLabelText("Proposed severity"), {
      target: { value: "critical" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Update example" }));

    await waitFor(() => {
      expect(put).toHaveBeenCalledWith(
        "/incidents/11111111-1111-1111-1111-111111111111/propose-severity",
        {
          proposed_severity: "critical",
          reason: "Updated reason",
        }
      );
    });
    expect(
      await screen.findByText("Example saved. Synced to knowledge base.")
    ).toBeInTheDocument();
  });

  it("deletes existing proposal", async () => {
    const get = jest.fn().mockResolvedValue({
      id: "proposal-1",
      incident_id: "11111111-1111-1111-1111-111111111111",
      incident_name: "Incident test",
      incident_status: "firing",
      current_severity: "warning",
      proposed_severity: "warning",
      reason: "Delete me",
      alerts_count: 1,
      created_by: "tester@keep.dev",
      created_at: "2026-02-27T10:00:00Z",
      sync_status: "synced",
      deduplicated: false,
    });
    const del = jest.fn().mockResolvedValue({
      id: "proposal-1",
      incident_id: "11111111-1111-1111-1111-111111111111",
      deleted: true,
      sync_status: "pending",
      sync_status_reason: "Queued",
    });
    mockedUseApi.mockReturnValue({
      get,
      post: jest.fn(),
      put: jest.fn(),
      delete: del,
    });

    render(
      <IncidentProposeSeverityModal
        incident={buildIncident()}
        isOpen={true}
        onClose={jest.fn()}
      />
    );

    await waitFor(() => {
      expect(get).toHaveBeenCalled();
    });

    fireEvent.click(await screen.findByRole("button", { name: "Delete example" }));

    await waitFor(() => {
      expect(del).toHaveBeenCalledWith(
        "/incidents/11111111-1111-1111-1111-111111111111/propose-severity"
      );
    });
    expect(
      await screen.findByText("Example deleted. Vector-store cleanup queued.")
    ).toBeInTheDocument();
  });
});
