# OpenAI Assistant Provider

Integrate OpenAI's Assistants API with Keep for advanced AI-powered alert triage and analysis.

## Features

### ✅ **Stateful Conversations**
Maintain context across multiple queries using threads. Perfect for complex troubleshooting.

### ✅ **File Search (Knowledge Base)**
Your assistant can search through uploaded documents, runbooks, and documentation to provide context-aware answers.

### ✅ **Code Interpreter**
Run Python code for data analysis, log parsing, and automated remediation.

### ✅ **Custom Instructions**
Define company-specific rules and knowledge in your assistant's system instructions.

---

## Setup

### 1. Create an OpenAI Assistant

1. Go to https://platform.openai.com/assistants
2. Click "Create" to make a new assistant
3. Configure:
   - **Name**: e.g., "Keep Alert Analyzer"
   - **Model**: `gpt-4o` or `gpt-4o-mini`
   - **Instructions**: Define your assistant's behavior
   ```
   You are an Alert Analysis Assistant for KeepHQ. You help on-call engineers 
   diagnose alerts by providing root-cause insights and actionable recommendations.
   Use the company knowledge base (uploaded files) to ground your answers.
   If information isn't in the knowledge base, say you don't have the info rather 
   than guessing. Keep responses concise, factual, and helpful.
   ```
   - **Tools**: Enable File Search and/or Code Interpreter
   - **Files**: Upload runbooks, documentation, past incident reports

4. Copy your assistant ID (starts with `asst_...`)

### 2. Configure in Keep

In Keep UI:
1. Go to **Providers** → **Add Provider**
2. Select **OpenAI Assistant**
3. Configure:
   - **API Key**: Your OpenAI API key (`sk-...`)
   - **Organization ID**: (Optional) Your OpenAI org ID
   - **Assistant ID**: The ID from step 1 (`asst_...`)
4. Test the connection
5. Save

---

## Usage

### Basic Query

```yaml
steps:
  - name: analyze_alert
    provider:
      type: openaiassistant
      config: "{{ providers.my_assistant }}"
      with:
        prompt: |
          Analyze this alert:
          {{ alert.message }}
```

### Continuing a Conversation

```yaml
steps:
  - name: initial_analysis
    provider:
      type: openaiassistant
      config: "{{ providers.my_assistant }}"
      with:
        prompt: "What's wrong with this server? CPU at 100%"
  
  - name: followup
    provider:
      type: openaiassistant
      config: "{{ providers.my_assistant }}"
      with:
        prompt: "What specific process should I kill first?"
        thread_id: "{{ steps.initial_analysis.results.thread_id }}"
```

### With Additional Instructions

```yaml
steps:
  - name: analyze_with_json
    provider:
      type: openaiassistant
      config: "{{ providers.my_assistant }}"
      with:
        prompt: "Analyze: {{ alert.message }}"
        additional_instructions: |
          Respond in JSON format with keys:
          - severity: "critical" | "high" | "medium" | "low"
          - action: "escalate" | "investigate" | "resolve"
          - reason: string explaining your decision
```

---

## Response Structure

The provider returns a dict with:

```python
{
    "response": "...",          # Parsed response (JSON dict if parseable, else string)
    "thread_id": "thread_...",  # For continuing conversation
    "run_id": "run_...",        # Unique run identifier
    "messages": [...],          # All messages in thread
    "raw_response": "...",      # Raw text response
}
```

Access in workflows:
- `{{ steps.analyze.results.response }}` - The main response
- `{{ steps.analyze.results.thread_id }}` - Thread ID for follow-ups
- `{{ steps.analyze.results.messages }}` - Full conversation history

---

## Comparison: OpenAI vs OpenAI Assistant

| Feature | OpenAI Provider | OpenAI Assistant Provider |
|---------|----------------|---------------------------|
| **API** | Chat Completions | Assistants API |
| **Speed** | Fast (~1-2s) | Slower (~5-10s, polling) |
| **Stateful** | No | Yes (threads) |
| **Knowledge Base** | No | Yes (File Search) |
| **Code Execution** | No | Yes (Code Interpreter) |
| **Structured Output** | Yes (JSON Schema) | Partial (depends on model) |
| **Cost** | Per token | Per token + tool usage |
| **Use Case** | Quick triage | Complex analysis with context |

### When to Use Each:

**Use OpenAI Provider for:**
- Fast, stateless queries
- Guaranteed JSON output
- Simple triage decisions
- High-volume alerts

**Use OpenAI Assistant Provider for:**
- Complex troubleshooting requiring context
- Queries needing company documentation
- Multi-step investigations
- Code analysis/execution

---

## Real-World Examples

### Example 1: Knowledge Base Search

**Setup:**
- Upload your runbooks, incident postmortems, and architecture docs to your assistant
- Enable File Search

**Workflow:**
```yaml
- name: search_runbooks
  provider:
    type: openaiassistant
    config: "{{ providers.my_assistant }}"
    with:
      prompt: |
        Alert: {{ alert.name }}
        Message: {{ alert.message }}
        
        Search our runbooks for:
        1. Similar past incidents
        2. Recommended troubleshooting steps
        3. Known issues and workarounds
```

The assistant will search your uploaded files and provide context-aware answers!

### Example 2: Log Analysis with Code Interpreter

**Setup:**
- Enable Code Interpreter in your assistant
- Upload recent logs as files (optional)

**Workflow:**
```yaml
- name: analyze_logs
  provider:
    type: openaiassistant
    config: "{{ providers.my_assistant }}"
    with:
      prompt: |
        Analyze these error logs:
        {{ alert.message }}
        
        Run Python code to:
        1. Parse the error patterns
        2. Count error frequencies
        3. Identify the root cause
        4. Suggest fixes
```

The assistant can run Python code to parse and analyze logs!

### Example 3: Multi-Step Incident Investigation

```yaml
workflow:
  id: incident-investigation
  
  actions:
    - name: initial_triage
      provider:
        type: openaiassistant
        config: "{{ providers.my_assistant }}"
        with:
          prompt: "Incident: {{ incident.name }}. What's the likely cause?"
    
    - name: ask_impact
      provider:
        type: openaiassistant
        config: "{{ providers.my_assistant }}"
        with:
          prompt: "What services are affected?"
          thread_id: "{{ steps.initial_triage.results.thread_id }}"
    
    - name: get_remediation
      provider:
        type: openaiassistant
        config: "{{ providers.my_assistant }}"
        with:
          prompt: "Provide step-by-step remediation"
          thread_id: "{{ steps.initial_triage.results.thread_id }}"
```

---

## Limitations

1. **Speed**: Assistants API is slower than Chat Completions (requires polling)
2. **Timeout**: Default 120s max wait time (configurable)
3. **Function Calling**: Not yet implemented in this provider (coming soon)
4. **Cost**: More expensive than Chat Completions due to tool usage

---

## Troubleshooting

### Assistant not responding
- Check your assistant ID is correct
- Verify API key has correct permissions
- Increase `max_wait_time` if assistant is slow

### "No response from assistant" error
- Your assistant might be stuck
- Check OpenAI platform for run status
- Try recreating the assistant

### JSON parsing fails
- Set `parse_json: false` to get raw text
- Add instructions asking for specific JSON format
- Use `additional_instructions` to enforce format

---

## Pricing

OpenAI Assistants pricing includes:
- **Base tokens**: Standard model pricing (input + output)
- **File Search**: $0.10 per GB per day (for uploaded files)
- **Code Interpreter**: $0.03 per session

**Example cost for 1000 alerts/day:**
- Using gpt-4o-mini: ~$5-10/month
- Using gpt-4o: ~$50-100/month

---

## Advanced: Custom Assistant Provider

You can extend this provider for your specific needs:

```python
from keep.providers.openaiassistant_provider import OpenaiAssistantProvider

class MyCustomAssistantProvider(OpenaiAssistantProvider):
    def _query(self, prompt, **kwargs):
        # Add custom pre-processing
        enriched_prompt = self.enrich_with_context(prompt)
        
        # Call parent
        result = super()._query(enriched_prompt, **kwargs)
        
        # Add custom post-processing
        result['custom_field'] = self.extract_something(result['response'])
        
        return result
```

---

## See Also

- [OpenAI Assistants Documentation](https://platform.openai.com/docs/assistants/overview)
- [Keep Workflows Documentation](https://docs.keephq.dev/workflows)
- [Example Workflow](../../../examples/workflows/ai_alert_triage_with_assistant.yaml)

