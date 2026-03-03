"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Badge,
  Button,
  Card,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow,
  Text,
  TextInput,
  Title,
} from "@tremor/react";
import { ArrowPathIcon, PlusIcon } from "@heroicons/react/24/outline";
import { useApi } from "@/shared/lib/hooks/useApi";
import Modal from "@/components/ui/Modal";

type ExampleScope = "alert" | "incident";
type Severity = "info" | "warning" | "high" | "critical";
type TriageMode = "single" | "batch";
type TriageRunStatus = "success" | "failed";

interface KBExample {
  id: string;
  tenant_id: string;
  scope: ExampleScope;
  proposed_severity: Severity;
  reason: string;
  alert_text: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  current_severity?: string | null;
  alert_id?: string | null;
  incident_id?: string | null;
  fingerprint?: string | null;
  source: string[];
  provider_id?: string | null;
  incident_alerts: Array<Record<string, unknown>>;
  metadata: Record<string, unknown>;
}

interface KBExamplesResponse {
  items: KBExample[];
  count: number;
}

interface TriageRunSummary {
  id: string;
  tenant_id: string;
  incident_id: string;
  mode: TriageMode;
  status: TriageRunStatus;
  recommended_severity?: Severity | null;
  reason?: string | null;
  error_message?: string | null;
  created_at: string;
  completed_at: string;
}

interface TriageRunsResponse {
  items: TriageRunSummary[];
  count: number;
}

interface TriageRunDetail extends TriageRunSummary {
  request_payload: Record<string, unknown>;
  retrieval_trace: Array<Record<string, unknown>>;
  llm_trace: Array<Record<string, unknown>>;
  response_payload?: Record<string, unknown> | null;
}

interface ExampleFormState {
  scope: ExampleScope;
  proposedSeverity: Severity;
  reason: string;
  alertText: string;
  currentSeverity: string;
  alertId: string;
  incidentId: string;
  fingerprint: string;
  sourceCsv: string;
  providerId: string;
  metadataJson: string;
  incidentAlertsJson: string;
}

const DEFAULT_FORM_STATE: ExampleFormState = {
  scope: "alert",
  proposedSeverity: "warning",
  reason: "",
  alertText: "",
  currentSeverity: "",
  alertId: "",
  incidentId: "",
  fingerprint: "",
  sourceCsv: "",
  providerId: "",
  metadataJson: "{}",
  incidentAlertsJson: "[]",
};

function safeJsonStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "{}";
  }
}

function getSeverityBadgeColor(severity?: string | null) {
  switch (severity) {
    case "critical":
      return "rose";
    case "high":
      return "red";
    case "warning":
      return "yellow";
    case "info":
      return "blue";
    default:
      return "gray";
  }
}

function parseJsonField<T>(raw: string, fieldName: string, fallback: T): T {
  const trimmed = raw.trim();
  if (!trimmed) {
    return fallback;
  }
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    throw new Error(`${fieldName} must be valid JSON.`);
  }
}

function toLocalDateTime(value: string) {
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

export function KnowledgeBasePage() {
  const api = useApi();
  const [activeTab, setActiveTab] = useState<"examples" | "logs">("examples");

  const [scopeFilter, setScopeFilter] = useState<"all" | ExampleScope>("all");
  const [examples, setExamples] = useState<KBExample[]>([]);
  const [examplesCount, setExamplesCount] = useState(0);
  const [isExamplesLoading, setIsExamplesLoading] = useState(false);
  const [examplesError, setExamplesError] = useState<string | null>(null);

  const [isExampleModalOpen, setIsExampleModalOpen] = useState(false);
  const [editingExample, setEditingExample] = useState<KBExample | null>(null);
  const [formState, setFormState] = useState<ExampleFormState>(DEFAULT_FORM_STATE);
  const [formError, setFormError] = useState<string | null>(null);
  const [formSuccess, setFormSuccess] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [logModeFilter, setLogModeFilter] = useState<"all" | TriageMode>("all");
  const [logIncidentFilter, setLogIncidentFilter] = useState("");
  const [logs, setLogs] = useState<TriageRunSummary[]>([]);
  const [logsCount, setLogsCount] = useState(0);
  const [isLogsLoading, setIsLogsLoading] = useState(false);
  const [logsError, setLogsError] = useState<string | null>(null);

  const [selectedLog, setSelectedLog] = useState<TriageRunDetail | null>(null);
  const [isLogModalOpen, setIsLogModalOpen] = useState(false);
  const [isLogDetailLoading, setIsLogDetailLoading] = useState(false);

  const loadExamples = useCallback(async () => {
    try {
      setIsExamplesLoading(true);
      setExamplesError(null);
      const params = new URLSearchParams({ limit: "200" });
      if (scopeFilter !== "all") {
        params.set("scope", scopeFilter);
      }
      const response = await api.get<KBExamplesResponse>(
        `/triage-kb/examples?${params.toString()}`
      );
      setExamples(response.items || []);
      setExamplesCount(response.count || 0);
    } catch (error) {
      setExamplesError(
        error instanceof Error ? error.message : "Failed loading examples."
      );
    } finally {
      setIsExamplesLoading(false);
    }
  }, [api, scopeFilter]);

  const loadLogs = useCallback(async () => {
    try {
      setIsLogsLoading(true);
      setLogsError(null);
      const params = new URLSearchParams({ limit: "200" });
      if (logModeFilter !== "all") {
        params.set("mode", logModeFilter);
      }
      if (logIncidentFilter.trim()) {
        params.set("incident_id", logIncidentFilter.trim());
      }
      const response = await api.get<TriageRunsResponse>(
        `/triage-kb/logs?${params.toString()}`
      );
      setLogs(response.items || []);
      setLogsCount(response.count || 0);
    } catch (error) {
      setLogsError(error instanceof Error ? error.message : "Failed loading logs.");
    } finally {
      setIsLogsLoading(false);
    }
  }, [api, logModeFilter, logIncidentFilter]);

  useEffect(() => {
    if (activeTab === "examples") {
      loadExamples();
    }
  }, [activeTab, loadExamples]);

  useEffect(() => {
    if (activeTab === "logs") {
      loadLogs();
    }
  }, [activeTab, loadLogs]);

  const openCreateModal = () => {
    setEditingExample(null);
    setFormState(DEFAULT_FORM_STATE);
    setFormError(null);
    setFormSuccess(null);
    setIsExampleModalOpen(true);
  };

  const openEditModal = (example: KBExample) => {
    setEditingExample(example);
    setFormState({
      scope: example.scope,
      proposedSeverity: example.proposed_severity,
      reason: example.reason || "",
      alertText: example.alert_text || "",
      currentSeverity: example.current_severity || "",
      alertId: example.alert_id || "",
      incidentId: example.incident_id || "",
      fingerprint: example.fingerprint || "",
      sourceCsv: (example.source || []).join(", "),
      providerId: example.provider_id || "",
      metadataJson: safeJsonStringify(example.metadata || {}),
      incidentAlertsJson: safeJsonStringify(example.incident_alerts || []),
    });
    setFormError(null);
    setFormSuccess(null);
    setIsExampleModalOpen(true);
  };

  const closeExampleModal = () => {
    if (isSubmitting) {
      return;
    }
    setIsExampleModalOpen(false);
  };

  const resetAndReloadExamples = async (message: string) => {
    setFormSuccess(message);
    await loadExamples();
  };

  const handleSubmitExample = async () => {
    if (isSubmitting) {
      return;
    }

    const normalizedReason = formState.reason.trim();
    const normalizedAlertText = formState.alertText.trim();
    if (normalizedReason.length < 3) {
      setFormError("Reason is required and must be at least 3 characters.");
      return;
    }
    if (normalizedAlertText.length < 3) {
      setFormError("Alert text is required and must be at least 3 characters.");
      return;
    }

    if (formState.scope === "alert" && !formState.alertId.trim() && !formState.fingerprint.trim()) {
      setFormError("For alert scope, set alert id or fingerprint.");
      return;
    }
    if (formState.scope === "incident" && !formState.incidentId.trim()) {
      setFormError("For incident scope, incident id is required.");
      return;
    }

    let metadata: Record<string, unknown>;
    let incidentAlerts: Array<Record<string, unknown>>;
    try {
      metadata = parseJsonField<Record<string, unknown>>(
        formState.metadataJson,
        "Metadata",
        {}
      );
      incidentAlerts = parseJsonField<Array<Record<string, unknown>>>(
        formState.incidentAlertsJson,
        "Incident alerts",
        []
      );
      if (!Array.isArray(incidentAlerts)) {
        throw new Error("Incident alerts must be a JSON array.");
      }
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Invalid JSON fields.");
      return;
    }

    const source = formState.sourceCsv
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

    const createPayload = {
      scope: formState.scope,
      proposed_severity: formState.proposedSeverity,
      reason: normalizedReason,
      alert_text: normalizedAlertText,
      current_severity: formState.currentSeverity.trim() || undefined,
      alert_id: formState.alertId.trim() || undefined,
      incident_id: formState.incidentId.trim() || undefined,
      fingerprint: formState.fingerprint.trim() || undefined,
      source,
      provider_id: formState.providerId.trim() || undefined,
      metadata,
      incident_alerts: incidentAlerts,
    };

    const updatePayload = {
      proposed_severity: formState.proposedSeverity,
      reason: normalizedReason,
      alert_text: normalizedAlertText,
      current_severity: formState.currentSeverity.trim() || undefined,
      source,
      provider_id: formState.providerId.trim() || undefined,
      metadata,
      incident_alerts: incidentAlerts,
    };

    try {
      setIsSubmitting(true);
      setFormError(null);
      if (editingExample) {
        await api.put(`/triage-kb/examples/${editingExample.id}`, updatePayload);
        await resetAndReloadExamples("Example updated.");
      } else {
        await api.post("/triage-kb/examples", createPayload);
        await resetAndReloadExamples("Example created.");
      }
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Failed saving example.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDeleteExample = async (example: KBExample) => {
    if (isSubmitting) {
      return;
    }
    const confirmed = window.confirm(
      `Delete example ${example.id}? This removes it from the local KB.`
    );
    if (!confirmed) {
      return;
    }
    try {
      setIsSubmitting(true);
      setFormError(null);
      await api.delete(`/triage-kb/examples/${example.id}`);
      await loadExamples();
    } catch (error) {
      setFormError(error instanceof Error ? error.message : "Failed deleting example.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const openLogDetail = async (runId: string) => {
    try {
      setIsLogDetailLoading(true);
      setLogsError(null);
      const response = await api.get<TriageRunDetail>(`/triage-kb/logs/${runId}`);
      setSelectedLog(response);
      setIsLogModalOpen(true);
    } catch (error) {
      setLogsError(
        error instanceof Error ? error.message : "Failed loading log details."
      );
    } finally {
      setIsLogDetailLoading(false);
    }
  };

  const exampleModalTitle = editingExample ? "Edit Example" : "Create Example";
  const exampleSubmitLabel = isSubmitting
    ? editingExample
      ? "Updating..."
      : "Creating..."
    : editingExample
      ? "Update Example"
      : "Create Example";

  const renderExampleTable = useMemo(() => {
    if (isExamplesLoading) {
      return <Text>Loading examples...</Text>;
    }
    if (examplesError) {
      return <Text className="text-red-600">{examplesError}</Text>;
    }
    if (!examples.length) {
      return <Text>No examples found for selected filters.</Text>;
    }

    return (
      <Table>
        <TableHead>
          <TableRow>
            <TableHeaderCell>Updated</TableHeaderCell>
            <TableHeaderCell>Scope</TableHeaderCell>
            <TableHeaderCell>Proposed</TableHeaderCell>
            <TableHeaderCell>Target</TableHeaderCell>
            <TableHeaderCell>Provider</TableHeaderCell>
            <TableHeaderCell>Reason</TableHeaderCell>
            <TableHeaderCell>Actions</TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {examples.map((example) => (
            <TableRow key={example.id}>
              <TableCell>{toLocalDateTime(example.updated_at)}</TableCell>
              <TableCell className="capitalize">{example.scope}</TableCell>
              <TableCell>
                <Badge color={getSeverityBadgeColor(example.proposed_severity)}>
                  {example.proposed_severity}
                </Badge>
              </TableCell>
              <TableCell>
                {example.scope === "incident"
                  ? example.incident_id || "-"
                  : example.alert_id || example.fingerprint || "-"}
              </TableCell>
              <TableCell>{example.provider_id || "-"}</TableCell>
              <TableCell className="max-w-[32rem] truncate" title={example.reason}>
                {example.reason}
              </TableCell>
              <TableCell>
                <div className="flex gap-2">
                  <Button
                    size="xs"
                    variant="secondary"
                    color="orange"
                    onClick={() => openEditModal(example)}
                  >
                    Edit
                  </Button>
                  <Button
                    size="xs"
                    variant="secondary"
                    color="red"
                    onClick={() => handleDeleteExample(example)}
                    disabled={isSubmitting}
                  >
                    Delete
                  </Button>
                </div>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  }, [
    isExamplesLoading,
    examplesError,
    examples,
    isSubmitting,
  ]);

  const renderLogsTable = useMemo(() => {
    if (isLogsLoading) {
      return <Text>Loading logs...</Text>;
    }
    if (logsError) {
      return <Text className="text-red-600">{logsError}</Text>;
    }
    if (!logs.length) {
      return <Text>No logs found for selected filters.</Text>;
    }

    return (
      <Table>
        <TableHead>
          <TableRow>
            <TableHeaderCell>Created</TableHeaderCell>
            <TableHeaderCell>Incident</TableHeaderCell>
            <TableHeaderCell>Mode</TableHeaderCell>
            <TableHeaderCell>Status</TableHeaderCell>
            <TableHeaderCell>Decision</TableHeaderCell>
            <TableHeaderCell>Reason</TableHeaderCell>
            <TableHeaderCell>Actions</TableHeaderCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {logs.map((log) => (
            <TableRow key={log.id}>
              <TableCell>{toLocalDateTime(log.created_at)}</TableCell>
              <TableCell>{log.incident_id}</TableCell>
              <TableCell className="capitalize">{log.mode}</TableCell>
              <TableCell>
                <Badge color={log.status === "success" ? "emerald" : "rose"}>
                  {log.status}
                </Badge>
              </TableCell>
              <TableCell>
                {log.recommended_severity ? (
                  <Badge color={getSeverityBadgeColor(log.recommended_severity)}>
                    {log.recommended_severity}
                  </Badge>
                ) : (
                  "-"
                )}
              </TableCell>
              <TableCell className="max-w-[24rem] truncate" title={log.reason || ""}>
                {log.error_message || log.reason || "-"}
              </TableCell>
              <TableCell>
                <Button
                  size="xs"
                  variant="secondary"
                  color="orange"
                  onClick={() => openLogDetail(log.id)}
                  disabled={isLogDetailLoading}
                >
                  {isLogDetailLoading ? "Loading..." : "View"}
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  }, [isLogsLoading, logsError, logs, isLogDetailLoading]);

  return (
    <div className="space-y-4">
      <Card className="p-4">
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
          <div>
            <Title>Triage Knowledge Base</Title>
            <Text>
              Manage alert/incident examples and inspect local LLM traces
              (request, retrieval, response).
            </Text>
          </div>
          <div className="flex gap-2">
            <Button
              color={activeTab === "examples" ? "orange" : "gray"}
              variant={activeTab === "examples" ? "primary" : "secondary"}
              onClick={() => setActiveTab("examples")}
            >
              Examples ({examplesCount})
            </Button>
            <Button
              color={activeTab === "logs" ? "orange" : "gray"}
              variant={activeTab === "logs" ? "primary" : "secondary"}
              onClick={() => setActiveTab("logs")}
            >
              LLM Logs ({logsCount})
            </Button>
          </div>
        </div>
      </Card>

      {activeTab === "examples" ? (
        <Card className="p-4 space-y-4">
          <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex gap-2 items-center">
              <Text>Scope</Text>
              <select
                className="rounded-md border border-gray-300 px-3 py-2 text-sm"
                value={scopeFilter}
                onChange={(event) =>
                  setScopeFilter(event.target.value as "all" | ExampleScope)
                }
              >
                <option value="all">All</option>
                <option value="alert">Alert</option>
                <option value="incident">Incident</option>
              </select>
              <Button
                size="xs"
                variant="secondary"
                icon={ArrowPathIcon}
                onClick={() => loadExamples()}
              >
                Refresh
              </Button>
            </div>
            <Button icon={PlusIcon} color="orange" onClick={openCreateModal}>
              New example
            </Button>
          </div>

          {renderExampleTable}
        </Card>
      ) : null}

      {activeTab === "logs" ? (
        <Card className="p-4 space-y-4">
          <div className="flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-wrap gap-2 items-center">
              <Text>Mode</Text>
              <select
                className="rounded-md border border-gray-300 px-3 py-2 text-sm"
                value={logModeFilter}
                onChange={(event) =>
                  setLogModeFilter(event.target.value as "all" | TriageMode)
                }
              >
                <option value="all">All</option>
                <option value="single">Single</option>
                <option value="batch">Batch</option>
              </select>
              <TextInput
                className="w-72"
                placeholder="Filter by incident id"
                value={logIncidentFilter}
                onChange={(event) => setLogIncidentFilter(event.target.value)}
              />
              <Button
                size="xs"
                variant="secondary"
                icon={ArrowPathIcon}
                onClick={() => loadLogs()}
              >
                Refresh
              </Button>
            </div>
          </div>

          {renderLogsTable}
        </Card>
      ) : null}

      <Modal
        isOpen={isExampleModalOpen}
        onClose={closeExampleModal}
        title={exampleModalTitle}
        description="Create or edit knowledge-base example records used by incident triage."
      >
        <div className="space-y-3">
          <label className="flex flex-col gap-1">
            <Text>Scope</Text>
            <select
              className="rounded-md border border-gray-300 px-3 py-2 text-sm"
              value={formState.scope}
              onChange={(event) =>
                setFormState((prev) => ({
                  ...prev,
                  scope: event.target.value as ExampleScope,
                }))
              }
              disabled={isSubmitting || !!editingExample}
            >
              <option value="alert">Alert</option>
              <option value="incident">Incident</option>
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <Text>Proposed severity</Text>
            <select
              className="rounded-md border border-gray-300 px-3 py-2 text-sm"
              value={formState.proposedSeverity}
              onChange={(event) =>
                setFormState((prev) => ({
                  ...prev,
                  proposedSeverity: event.target.value as Severity,
                }))
              }
              disabled={isSubmitting}
            >
              <option value="info">Info</option>
              <option value="warning">Warning</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <Text>Reason</Text>
            <textarea
              className="min-h-20 rounded-md border border-gray-300 px-3 py-2 text-sm"
              value={formState.reason}
              onChange={(event) =>
                setFormState((prev) => ({ ...prev, reason: event.target.value }))
              }
              disabled={isSubmitting}
            />
          </label>

          <label className="flex flex-col gap-1">
            <Text>Alert text</Text>
            <textarea
              className="min-h-24 rounded-md border border-gray-300 px-3 py-2 text-sm"
              value={formState.alertText}
              onChange={(event) =>
                setFormState((prev) => ({ ...prev, alertText: event.target.value }))
              }
              disabled={isSubmitting}
            />
          </label>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="flex flex-col gap-1">
              <Text>Current severity</Text>
              <TextInput
                value={formState.currentSeverity}
                onChange={(event) =>
                  setFormState((prev) => ({
                    ...prev,
                    currentSeverity: event.target.value,
                  }))
                }
                disabled={isSubmitting}
              />
            </label>

            {formState.scope === "alert" ? (
              <>
                <label className="flex flex-col gap-1">
                  <Text>Alert id</Text>
                  <TextInput
                    value={formState.alertId}
                    onChange={(event) =>
                      setFormState((prev) => ({
                        ...prev,
                        alertId: event.target.value,
                      }))
                    }
                    disabled={isSubmitting}
                  />
                </label>
                <label className="flex flex-col gap-1">
                  <Text>Fingerprint</Text>
                  <TextInput
                    value={formState.fingerprint}
                    onChange={(event) =>
                      setFormState((prev) => ({
                        ...prev,
                        fingerprint: event.target.value,
                      }))
                    }
                    disabled={isSubmitting}
                  />
                </label>
              </>
            ) : (
              <label className="flex flex-col gap-1">
                <Text>Incident id</Text>
                <TextInput
                  value={formState.incidentId}
                  onChange={(event) =>
                    setFormState((prev) => ({
                      ...prev,
                      incidentId: event.target.value,
                    }))
                  }
                  disabled={isSubmitting}
                />
              </label>
            )}

            <label className="flex flex-col gap-1">
              <Text>Provider id</Text>
              <TextInput
                value={formState.providerId}
                onChange={(event) =>
                  setFormState((prev) => ({ ...prev, providerId: event.target.value }))
                }
                disabled={isSubmitting}
              />
            </label>

            <label className="flex flex-col gap-1">
              <Text>Source (comma-separated)</Text>
              <TextInput
                value={formState.sourceCsv}
                onChange={(event) =>
                  setFormState((prev) => ({ ...prev, sourceCsv: event.target.value }))
                }
                disabled={isSubmitting}
              />
            </label>
          </div>

          <label className="flex flex-col gap-1">
            <Text>Metadata (JSON)</Text>
            <textarea
              className="min-h-20 rounded-md border border-gray-300 px-3 py-2 text-sm font-mono"
              value={formState.metadataJson}
              onChange={(event) =>
                setFormState((prev) => ({
                  ...prev,
                  metadataJson: event.target.value,
                }))
              }
              disabled={isSubmitting}
            />
          </label>

          <label className="flex flex-col gap-1">
            <Text>Incident alerts snapshot (JSON array)</Text>
            <textarea
              className="min-h-20 rounded-md border border-gray-300 px-3 py-2 text-sm font-mono"
              value={formState.incidentAlertsJson}
              onChange={(event) =>
                setFormState((prev) => ({
                  ...prev,
                  incidentAlertsJson: event.target.value,
                }))
              }
              disabled={isSubmitting}
            />
          </label>

          {formError ? <Text className="text-red-600">{formError}</Text> : null}
          {formSuccess ? <Text className="text-green-700">{formSuccess}</Text> : null}
        </div>

        <div className="mt-4 flex justify-end gap-2">
          <Button
            variant="secondary"
            color="orange"
            onClick={closeExampleModal}
            disabled={isSubmitting}
          >
            Close
          </Button>
          <Button color="orange" onClick={handleSubmitExample} disabled={isSubmitting}>
            {exampleSubmitLabel}
          </Button>
        </div>
      </Modal>

      <Modal
        isOpen={isLogModalOpen}
        onClose={() => setIsLogModalOpen(false)}
        title="LLM Trace"
        beforeTitle={selectedLog?.incident_id || ""}
      >
        {selectedLog ? (
          <div className="space-y-3 max-h-[70vh] overflow-auto">
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              <Text>
                <b>Run:</b> {selectedLog.id}
              </Text>
              <Text>
                <b>Mode:</b> {selectedLog.mode}
              </Text>
              <Text>
                <b>Status:</b> {selectedLog.status}
              </Text>
              <Text>
                <b>Decision:</b> {selectedLog.recommended_severity || "-"}
              </Text>
            </div>

            <div>
              <Text className="font-semibold">Request payload</Text>
              <pre className="mt-1 rounded bg-slate-50 p-2 text-xs overflow-auto">
                {safeJsonStringify(selectedLog.request_payload)}
              </pre>
            </div>

            <div>
              <Text className="font-semibold">Retrieval trace (top results used)</Text>
              <pre className="mt-1 rounded bg-slate-50 p-2 text-xs overflow-auto">
                {safeJsonStringify(selectedLog.retrieval_trace)}
              </pre>
            </div>

            <div>
              <Text className="font-semibold">LLM trace (request/response)</Text>
              <pre className="mt-1 rounded bg-slate-50 p-2 text-xs overflow-auto">
                {safeJsonStringify(selectedLog.llm_trace)}
              </pre>
            </div>

            <div>
              <Text className="font-semibold">Final response</Text>
              <pre className="mt-1 rounded bg-slate-50 p-2 text-xs overflow-auto">
                {safeJsonStringify(selectedLog.response_payload || {})}
              </pre>
            </div>
          </div>
        ) : (
          <Text>No log selected.</Text>
        )}

        <div className="mt-4 flex justify-end">
          <Button
            variant="secondary"
            color="orange"
            onClick={() => setIsLogModalOpen(false)}
          >
            Close
          </Button>
        </div>
      </Modal>
    </div>
  );
}
