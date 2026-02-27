"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertDto } from "@/entities/alerts/model";
import Modal from "@/components/ui/Modal";
import { Button, Text } from "@tremor/react";
import { useApi } from "@/shared/lib/hooks/useApi";

type ProposedSeverity = "info" | "warning" | "high" | "critical";
type SyncStatus = "pending" | "synced" | "failed";

interface ProposalResponse {
  id: string;
  alert_id: string;
  alert_fingerprint: string;
  current_severity: string;
  proposed_severity: ProposedSeverity;
  reason: string;
  created_by: string;
  created_at: string;
  updated_by?: string | null;
  updated_at?: string | null;
  deleted_at?: string | null;
  sync_status: SyncStatus;
  sync_status_reason?: string | null;
  deduplicated: boolean;
}

interface ProposalDeleteResponse {
  id: string;
  alert_id: string;
  deleted: boolean;
  sync_status: SyncStatus;
  sync_status_reason?: string | null;
}

interface AlertProposeSeverityModalProps {
  alert: AlertDto | null;
  isOpen: boolean;
  onClose: () => void;
}

const severityOptions: { value: ProposedSeverity; label: string }[] = [
  { value: "info", label: "Info" },
  { value: "warning", label: "Warning" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
];

function buildSuccessMessage(response: ProposalResponse) {
  const prefix = response.deduplicated
    ? "Example already exists."
    : "Example saved.";
  if (response.sync_status === "synced") {
    return `${prefix} Synced to knowledge base.`;
  }
  if (response.sync_status === "pending") {
    return `${prefix} Sync queued.`;
  }
  return `${prefix} Sync failed: ${response.sync_status_reason || "unknown error"}.`;
}

function buildDeleteSuccessMessage(response: ProposalDeleteResponse) {
  if (response.sync_status === "synced") {
    return "Example deleted and removed from knowledge base.";
  }
  if (response.sync_status === "pending") {
    return "Example deleted. Vector-store cleanup queued.";
  }
  return `Example deleted locally but cleanup failed: ${response.sync_status_reason || "unknown error"}.`;
}

export function AlertProposeSeverityModal({
  alert,
  isOpen,
  onClose,
}: AlertProposeSeverityModalProps) {
  const api = useApi();
  const [existingProposal, setExistingProposal] = useState<ProposalResponse | null>(
    null
  );
  const [proposedSeverity, setProposedSeverity] =
    useState<ProposedSeverity>("warning");
  const [reason, setReason] = useState("");
  const [isLoadingProposal, setIsLoadingProposal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen || !alert?.event_id) {
      return;
    }
    let cancelled = false;
    setIsLoadingProposal(true);
    setIsSubmitting(false);
    setIsDeleting(false);
    setErrorMessage(null);
    setSuccessMessage(null);
    setExistingProposal(null);
    setProposedSeverity("warning");
    setReason("");

    const loadExistingProposal = async () => {
      try {
        const response = await api.get<ProposalResponse>(
          `/alerts/event/${alert.event_id}/propose-severity`
        );
        if (cancelled) {
          return;
        }
        setExistingProposal(response);
        setProposedSeverity(response.proposed_severity);
        setReason(response.reason || "");
      } catch (error) {
        if (cancelled) {
          return;
        }
        const msg = error instanceof Error ? error.message : "Failed loading proposal.";
        if (!msg.includes("404")) {
          setErrorMessage(msg);
        }
      } finally {
        if (!cancelled) {
          setIsLoadingProposal(false);
        }
      }
    };

    loadExistingProposal();
    return () => {
      cancelled = true;
    };
  }, [isOpen, alert?.event_id]);

  const canSubmit = useMemo(() => {
    return (
      !!alert?.event_id &&
      reason.trim().length > 0 &&
      !isSubmitting &&
      !isDeleting &&
      !isLoadingProposal
    );
  }, [alert?.event_id, reason, isSubmitting, isDeleting, isLoadingProposal]);

  if (!alert) {
    return null;
  }

  const handleSubmit = async () => {
    const normalizedReason = reason.trim();
    if (!alert.event_id) {
      setErrorMessage("Alert event id is missing. Please refresh and retry.");
      return;
    }
    if (normalizedReason.length < 3) {
      setErrorMessage("Reason is required and must be at least 3 characters.");
      return;
    }
    if (isSubmitting || isDeleting) {
      return;
    }

    try {
      setIsSubmitting(true);
      setErrorMessage(null);
      const endpoint = `/alerts/event/${alert.event_id}/propose-severity`;
      const payload = {
        proposed_severity: proposedSeverity,
        reason: normalizedReason,
      };
      const response = existingProposal
        ? await api.put<ProposalResponse>(endpoint, payload)
        : await api.post<ProposalResponse>(endpoint, payload);
      setExistingProposal(response);
      setProposedSeverity(response.proposed_severity);
      setReason(response.reason);
      setSuccessMessage(buildSuccessMessage(response));
    } catch (error) {
      const msg =
        error instanceof Error
          ? error.message
          : "Failed to save severity proposal.";
      setErrorMessage(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!alert.event_id || !existingProposal || isSubmitting || isDeleting) {
      return;
    }

    try {
      setIsDeleting(true);
      setErrorMessage(null);
      const response = await api.delete<ProposalDeleteResponse>(
        `/alerts/event/${alert.event_id}/propose-severity`
      );
      setExistingProposal(null);
      setProposedSeverity("warning");
      setReason("");
      setSuccessMessage(buildDeleteSuccessMessage(response));
    } catch (error) {
      const msg =
        error instanceof Error
          ? error.message
          : "Failed to delete severity proposal.";
      setErrorMessage(msg);
    } finally {
      setIsDeleting(false);
    }
  };

  const isBusy = isLoadingProposal || isSubmitting || isDeleting;
  const isMutating = isSubmitting || isDeleting;

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Propose severity"
      beforeTitle={alert.name}
      description="Save this alert as a triage example for the knowledge base."
    >
      <div className="flex flex-col gap-3">
        {isLoadingProposal ? (
          <Text className="text-gray-600">Loading existing example...</Text>
        ) : null}
        <label className="flex flex-col gap-1">
          <Text>Proposed severity</Text>
          <select
            className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-400"
            value={proposedSeverity}
            onChange={(e) => setProposedSeverity(e.target.value as ProposedSeverity)}
            disabled={isBusy}
          >
            {severityOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <Text>Reason</Text>
          <textarea
            className="min-h-28 w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-orange-400"
            placeholder="Explain why this alert should have the selected severity."
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            disabled={isBusy}
            required
          />
        </label>
        {errorMessage ? <Text className="text-red-600">{errorMessage}</Text> : null}
        {successMessage ? (
          <Text className="text-green-700">{successMessage}</Text>
        ) : null}
      </div>
      <div className="mt-4 flex justify-end gap-2">
        {existingProposal ? (
          <Button
            onClick={handleDelete}
            variant="secondary"
            color="red"
            disabled={isBusy}
          >
            {isDeleting ? "Deleting..." : "Delete example"}
          </Button>
        ) : null}
        <Button
          onClick={onClose}
          variant="secondary"
          color="orange"
          disabled={isMutating}
        >
          Close
        </Button>
        <Button onClick={handleSubmit} color="orange" disabled={!canSubmit}>
          {isSubmitting
            ? existingProposal
              ? "Updating..."
              : "Saving..."
            : existingProposal
              ? "Update example"
              : "Save example"}
        </Button>
      </div>
    </Modal>
  );
}
