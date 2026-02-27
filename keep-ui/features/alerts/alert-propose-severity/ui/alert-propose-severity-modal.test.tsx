import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AlertProposeSeverityModal } from "./alert-propose-severity-modal";
import { AlertDto } from "@/entities/alerts/model";
import { useApi } from "@/shared/lib/hooks/useApi";

const mockedUseApi = useApi as jest.Mock;

function buildAlert(overrides: Partial<AlertDto> = {}): AlertDto {
  return {
    id: "1",
    event_id: "11111111-1111-1111-1111-111111111111",
    name: "Test Alert",
    status: "firing" as AlertDto["status"],
    severity: "warning" as AlertDto["severity"],
    lastReceived: new Date(),
    environment: "prod",
    source: ["mailgun"],
    pushed: true,
    fingerprint: "fp-1",
    deleted: false,
    dismissed: false,
    ticket_url: "",
    enriched_fields: [],
    ...overrides,
  };
}

describe("AlertProposeSeverityModal", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("creates a proposal and shows queued success state", async () => {
    const get = jest.fn().mockRejectedValue(new Error("404"));
    const post = jest.fn().mockResolvedValue({
      id: "proposal-1",
      alert_id: "11111111-1111-1111-1111-111111111111",
      alert_fingerprint: "fp-1",
      current_severity: "info",
      proposed_severity: "info",
      reason: "This is informational and should auto-resolve.",
      created_by: "tester@keep.dev",
      created_at: "2026-02-26T10:00:00Z",
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
      <AlertProposeSeverityModal
        alert={buildAlert()}
        isOpen={true}
        onClose={jest.fn()}
      />
    );

    await waitFor(() => {
      expect(get).toHaveBeenCalled();
    });

    fireEvent.change(screen.getByLabelText("Reason"), {
      target: { value: "This is informational and should auto-resolve." },
    });
    fireEvent.change(screen.getByLabelText("Proposed severity"), {
      target: { value: "info" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save example" }));

    await waitFor(() => {
      expect(post).toHaveBeenCalledWith(
        "/alerts/event/11111111-1111-1111-1111-111111111111/propose-severity",
        {
          proposed_severity: "info",
          reason: "This is informational and should auto-resolve.",
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
      alert_id: "11111111-1111-1111-1111-111111111111",
      alert_fingerprint: "fp-1",
      current_severity: "warning",
      proposed_severity: "warning",
      reason: "Initial reason",
      created_by: "tester@keep.dev",
      created_at: "2026-02-26T10:00:00Z",
      sync_status: "synced",
      deduplicated: false,
    });
    const put = jest.fn().mockResolvedValue({
      id: "proposal-1",
      alert_id: "11111111-1111-1111-1111-111111111111",
      alert_fingerprint: "fp-1",
      current_severity: "warning",
      proposed_severity: "critical",
      reason: "Updated reason",
      created_by: "tester@keep.dev",
      created_at: "2026-02-26T10:00:00Z",
      updated_by: "tester@keep.dev",
      updated_at: "2026-02-26T11:00:00Z",
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
      <AlertProposeSeverityModal
        alert={buildAlert()}
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
        "/alerts/event/11111111-1111-1111-1111-111111111111/propose-severity",
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
      alert_id: "11111111-1111-1111-1111-111111111111",
      alert_fingerprint: "fp-1",
      current_severity: "warning",
      proposed_severity: "warning",
      reason: "Delete me",
      created_by: "tester@keep.dev",
      created_at: "2026-02-26T10:00:00Z",
      sync_status: "synced",
      deduplicated: false,
    });
    const del = jest.fn().mockResolvedValue({
      id: "proposal-1",
      alert_id: "11111111-1111-1111-1111-111111111111",
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
      <AlertProposeSeverityModal
        alert={buildAlert()}
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
        "/alerts/event/11111111-1111-1111-1111-111111111111/propose-severity"
      );
    });
    expect(
      await screen.findByText("Example deleted. Vector-store cleanup queued.")
    ).toBeInTheDocument();
  });
});
